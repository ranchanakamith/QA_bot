"""Discovery: fetch the start page (smoke test), crawl same-origin pages, verify links."""
from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from urllib import robotparser
from urllib.parse import urljoin

import requests
import urllib3
from bs4 import BeautifulSoup

from .http import describe_error, set_cookie_headers
from .models import Page, ScanContext
from .util import is_http_url, looks_like_page, normalize, origin_of, same_origin

MAX_HTML_BYTES = 3_000_000
RESOURCE_SELECTORS = (
    ("image", "img[src]", "src"),
    ("script", "script[src]", "src"),
    ("stylesheet", "link[rel~=stylesheet][href]", "href"),
    ("frame", "iframe[src]", "src"),
    ("media", "video[src], audio[src], source[src]", "src"),
)
# Statuses that mean "the site refused a bot", not "the link is broken".
BLOCKED_STATUSES = {401, 403, 405, 429, 999}


def soup_of(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:  # lxml missing or failed
        return BeautifulSoup(html, "html.parser")


def fetch_page(ctx: ScanContext, url: str, depth: int = 0, referrer: str | None = None) -> Page:
    page = Page(url=url, depth=depth, referrer=referrer, final_url=url)
    try:
        resp = ctx.http.get(url)
    except requests.RequestException as exc:
        page.error = describe_error(exc)
        if isinstance(exc, requests.exceptions.SSLError) and not ctx.tls_error:
            ctx.tls_error = str(exc)
        ctx.request_log.append({"url": url, "status": None, "error": page.error, "ms": 0})
        return page
    page.status = resp.status_code
    page.final_url = normalize(resp.url)
    page.headers = resp.headers
    page.set_cookies = set_cookie_headers(resp)
    page.redirects = [r.url for r in resp.history]
    page.content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    page.elapsed_ms = resp.elapsed.total_seconds() * 1000
    page.size_bytes = len(resp.content)
    if "html" in page.content_type and page.size_bytes <= MAX_HTML_BYTES:
        page.html = resp.text
    ctx.request_log.append({"url": url, "status": page.status, "error": "", "ms": round(page.elapsed_ms)})
    return page


def extract(page: Page) -> None:
    """Fill page.links, page.resources and page.forms from the rendered (or served) HTML."""
    soup = soup_of(page.dom)
    base = page.final_url
    base_tag = soup.find("base", href=True)
    if base_tag:
        base = urljoin(base, base_tag["href"])

    def absolute(value: str) -> str | None:
        value = (value or "").strip()
        if not value or value.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:", "about:")):
            return None
        url = urljoin(base, value)
        return normalize(url) if is_http_url(url) else None

    seen = set()
    for a in soup.select("a[href]"):
        url = absolute(a["href"])
        if url and url not in seen:
            seen.add(url)
            page.links.append((url, a.get_text(" ", strip=True)[:80]))

    seen = set()
    for kind, selector, attr in RESOURCE_SELECTORS:
        for el in soup.select(selector):
            url = absolute(el.get(attr, ""))
            if url and url not in seen:
                seen.add(url)
                page.resources.append((kind, url))

    for form in soup.find_all("form"):
        inputs = [{"name": i.get("name", ""), "type": (i.get("type") or i.name).lower()}
                  for i in form.find_all(["input", "select", "textarea"])]
        page.forms.append({
            "action": absolute(form.get("action", "")) or page.final_url,
            "method": (form.get("method") or "get").lower(),
            "inputs": inputs,
            "has_password": any(i["type"] == "password" for i in inputs),
        })


def load_robots(ctx: ScanContext):
    if not ctx.config["crawl"]["respect_robots"]:
        return None
    try:
        resp = ctx.http.get(ctx.origin + "/robots.txt")
    except requests.RequestException:
        return None
    if resp.status_code != 200 or "html" in resp.headers.get("Content-Type", ""):
        return None
    parser = robotparser.RobotFileParser()
    parser.parse(resp.text.splitlines())
    return parser


def crawl(ctx: ScanContext, start_page: Page) -> None:
    """Breadth-first crawl of same-origin pages, starting from the already-fetched start page."""
    cfg = ctx.config["crawl"]
    robots = load_robots(ctx)
    agent = cfg["user_agent"]
    queued = {normalize(start_page.url), start_page.final_url}
    queue: deque = deque()

    def process(page: Page) -> None:
        ctx.pages.append(page)
        if not page.is_html or not same_origin(page.final_url, ctx.origin):
            return
        if ctx.browser is not None:
            ctx.browser.visit(page)
        extract(page)
        for kind, urls in (("link", [u for u, _ in page.links]), ("resource", [u for _, u in page.resources])):
            for url in urls:
                ctx.link_sources.setdefault(url, set()).add(page.final_url)
                ctx.link_kinds.setdefault(url, kind)
        if page.status and page.status >= 400:
            return
        for url, _ in page.links:
            if (url not in queued and same_origin(url, ctx.origin) and looks_like_page(url)
                    and page.depth < cfg["max_depth"]):
                queued.add(url)
                queue.append((url, page.depth + 1, page.final_url))

    process(start_page)
    while queue and len(ctx.pages) < cfg["max_pages"]:
        url, depth, referrer = queue.popleft()
        if robots is not None and not robots.can_fetch(agent, url):
            ctx.skipped_by_robots.append(url)
            continue
        process(fetch_page(ctx, url, depth, referrer))
    if queue:
        ctx.note(f"Crawl stopped at the {cfg['max_pages']}-page limit; {len(queue)} discovered pages were not opened "
                 "(their links were still checked).")


def _probe(ctx: ScanContext, url: str, throttle: bool) -> dict:
    """Status of one URL: HEAD first, GET when the server mishandles HEAD."""
    try:
        resp = ctx.http.request("HEAD", url, throttle=throttle)
        if resp.status_code >= 400:
            resp = ctx.http.request("GET", url, throttle=throttle, stream=True)
            resp.close()
        return {"status": resp.status_code, "error": ""}
    except requests.RequestException as exc:
        return {"status": None, "error": describe_error(exc)}


def verify_links(ctx: ScanContext) -> None:
    """Decide for every referenced URL whether it is ok, broken, blocked or unchecked."""
    cfg = ctx.config["crawl"]
    crawled = {}
    for page in ctx.pages:
        entry = {"status": page.status, "error": page.error}
        crawled[normalize(page.url)] = entry
        crawled[page.final_url] = entry

    internal, external = [], []
    for url in ctx.link_sources:
        if url in crawled:
            ctx.link_status[url] = dict(crawled[url])
        elif same_origin(url, ctx.origin):
            internal.append(url)
        else:
            external.append(url)

    for url in internal[: cfg["max_link_checks"]]:
        result = _probe(ctx, url, throttle=True)
        ctx.request_log.append({"url": url, "status": result["status"], "error": result["error"], "ms": 0})
        ctx.link_status[url] = result
    for url in internal[cfg["max_link_checks"]:]:
        ctx.link_status[url] = {"status": None, "error": "", "state": "unchecked"}

    to_check = external[: cfg["max_external"]] if cfg["check_external"] else []
    if to_check:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda u: _probe(ctx, u, throttle=False), to_check))
        # If nothing outside the site answers, the machine is probably offline: do not blame the site.
        if all(r["status"] is None for r in results):
            ctx.note("No external link could be reached from this machine, so external links were not verified.")
            to_check = []
        else:
            for url, result in zip(to_check, results):
                ctx.link_status[url] = result
    for url in external:
        ctx.link_status.setdefault(url, {"status": None, "error": "", "state": "unchecked"})

    for url, entry in ctx.link_status.items():
        if entry.get("state"):
            continue
        status = entry["status"]
        if status is None:
            entry["state"] = "broken"
        elif status in BLOCKED_STATUSES and not same_origin(url, ctx.origin):
            entry["state"] = "blocked"
        elif status >= 500:
            entry["state"] = "server_error"
        elif status >= 400:
            entry["state"] = "broken"
        else:
            entry["state"] = "ok"


def has_content(page: Page) -> bool:
    soup = soup_of(page.html)
    return bool(soup.body and soup.body.get_text(strip=True)) or bool(soup.title and soup.title.get_text(strip=True))


def smoke_test(ctx: ScanContext) -> tuple:
    """Stage 2 of the pipeline: is the site up and does the home page render something?"""
    try:
        page = fetch_page(ctx, ctx.target)
        if page.error == "TLS error":
            # The certificate problem is recorded; carry on unverified so the other checks can run.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            ctx.http.verify = False
            ctx.request_log.clear()
            page = fetch_page(ctx, ctx.target)
    except Exception as exc:  # defensive: a smoke test must always return a verdict
        return None, f"could not request the site ({type(exc).__name__})"
    if page.error:
        return page, f"the site did not answer ({page.error})"
    if page.status >= 400:
        return page, f"the start page returned HTTP {page.status}"
    if not page.is_html:
        return page, f"the start page is not HTML (content type '{page.content_type or 'unknown'}')"
    if not has_content(page):
        return page, "the start page is empty"
    if not same_origin(page.final_url, ctx.origin):
        # http -> https or example.com -> www.example.com: scan the site the visitor actually lands on.
        ctx.note(f"{ctx.target} redirects to {page.final_url}; that site was scanned.")
        ctx.redirected_from = ctx.origin
        ctx.origin = origin_of(page.final_url)
    return page, ""
