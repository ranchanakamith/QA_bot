"""The scan pipeline: smoke test -> discovery -> checks -> score."""
from __future__ import annotations

import datetime as dt
import time
import traceback
from dataclasses import asdict
from urllib.parse import urlsplit

from . import __version__, checks
from .browser import BrowserSession
from .crawler import crawl, smoke_test, verify_links
from .http import HttpClient
from .models import CheckResult, ScanContext
from .scoring import assign_impact, compute, fix_order
from .util import is_local_host, normalize, origin_of


def run_scan(target: str, cfg: dict, profile: str = "general", owned: bool = False, log=print) -> dict:
    """Runs a full scan and returns the report data (a plain dict, ready for JSON)."""
    if "://" not in target:
        target = "http://" + target if is_local_host(target.split(":")[0].split("/")[0]) else "https://" + target
    target = normalize(target)
    started = dt.datetime.now(dt.timezone.utc)
    clock = time.monotonic()
    ctx = ScanContext(target=target, origin=origin_of(target), config=cfg, owned=owned,
                      is_local=is_local_host(urlsplit(target).hostname or ""))
    ctx.http = HttpClient(cfg["crawl"])
    results: list = []
    smoke_reason = ""
    browser_note = ""
    try:
        log(f"[1/5] Smoke test: {target}")
        start_page, smoke_reason = smoke_test(ctx)
        if smoke_reason:
            log(f"      FAILED: {smoke_reason}")
        else:
            ctx.browser, browser_note = BrowserSession.try_start(cfg, ignore_https_errors=bool(ctx.tls_error))
            if ctx.browser is None:
                ctx.note(f"Browser checks were skipped: {browser_note}.")
                log(f"      No browser: {browser_note}")
            log(f"[2/5] Discovery: crawling up to {cfg['crawl']['max_pages']} pages")
            crawl(ctx, start_page)
            log(f"      {len(ctx.pages)} pages, {len(ctx.link_sources)} links and resources")
            log("[3/5] Verifying links and resources")
            verify_links(ctx)
            log("[4/5] Running checks")
            for run in checks.ALL:
                name = run.__module__.rsplit(".", 1)[-1]
                try:
                    produced = run(ctx)
                except Exception as exc:  # one broken check must not lose the whole scan
                    traceback.print_exc()
                    ctx.note(f"The {name} checks stopped with an internal error ({type(exc).__name__}: {exc}) and were not scored.")
                    produced = []
                for result in produced:
                    state = f"{result.score:.0f}" if result.tested and result.score is not None else "not tested"
                    log(f"      {name}.{result.id}: {state}")
                results.extend(produced)
        log("[5/5] Scoring")
        scorecard = compute(results, cfg, profile, smoke_failed=bool(smoke_reason))
        findings = assign_impact(results, scorecard, cfg)
    finally:
        ctx.http.close()
        browser_version = ctx.browser.version if ctx.browser is not None else ""
        if ctx.browser is not None:
            ctx.browser.close()

    return {
        "tool": "qabot", "version": __version__,
        "target": target, "scanned_origin": ctx.origin,
        "started": started.isoformat(timespec="seconds"),
        "duration_seconds": round(time.monotonic() - clock, 1),
        "profile": profile,
        "access": "Black-box (URL only)" + (", ownership confirmed by the user" if owned else ""),
        "smoke": {"passed": not smoke_reason, "reason": smoke_reason},
        "browser": f"Chromium {browser_version}" if browser_version else "",
        "score": scorecard,
        "findings": [asdict(f) for f in findings],
        "fix_list": [f.id for f in fix_order(findings)],
        "not_tested": [{"category": cat["name"], "check": chk["name"], "reason": chk["reason"]}
                       for cat in scorecard["categories"] for chk in cat["checks"] if not chk["tested"]],
        "check_details": {r.id: r.details for r in results if r.tested},
        "pages": [{"url": p.final_url, "status": p.status, "error": p.error, "ms": round(p.elapsed_ms),
                   "bytes": p.size_bytes, "depth": p.depth} for p in ctx.pages],
        "inventory": {
            "pages": len(ctx.pages),
            "links_and_resources": len(ctx.link_sources),
            "forms": sum(len(p.forms) for p in ctx.pages),
            "forms_with_password": sum(1 for p in ctx.pages for f in p.forms if f["has_password"]),
            "skipped_by_robots": len(ctx.skipped_by_robots),
        },
        "notes": ctx.notes,
        "screenshots": ctx.screenshots,
    }


def compare(report: dict, baseline: dict) -> None:
    """Adds score changes against an earlier report (confirmation and regression runs)."""
    before = {c["id"]: c["score"] for c in baseline["score"]["categories"]}
    for cat in report["score"]["categories"]:
        old = before.get(cat["id"])
        cat["delta"] = round(cat["score"] - old, 1) if cat["score"] is not None and old is not None else None
    old_rules = {f["rule"] for f in baseline["findings"]}
    new_rules = {f["rule"] for f in report["findings"]}
    report["baseline"] = {
        "started": baseline.get("started", ""),
        "score": baseline["score"]["score"],
        "delta": report["score"]["score"] - baseline["score"]["score"],
        "fixed": sorted(old_rules - new_rules),
        "new": sorted(new_rules - old_rules),
    }
