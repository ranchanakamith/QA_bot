"""Functional correctness, Phase 1: links, resources and JavaScript errors."""
from __future__ import annotations

from ..models import CheckResult, FindingSet, ScanContext
from ..scoring import pass_rate_score
from ..util import same_origin, short

CATEGORY = "functional"


def run(ctx: ScanContext) -> list:
    return [links_resources(ctx)]


def links_resources(ctx: ScanContext) -> CheckResult:
    findings = FindingSet(CATEGORY, "links_resources")
    counts = {"link": [0, 0], "resource": [0, 0]}      # kind -> [verified, broken]
    unverified = 0

    for url, entry in ctx.link_status.items():
        kind = ctx.link_kinds.get(url, "link")
        state = entry["state"]
        if state in ("unchecked", "blocked"):
            unverified += 1
            continue
        if state == "server_error":
            continue                                    # 5xx is scored under reliability, once
        counts[kind][0] += 1
        if state != "broken":
            continue
        counts[kind][1] += 1
        internal = same_origin(url, ctx.origin)
        what = "link" if kind == "link" else "resource"
        outcome = f"HTTP {entry['status']}" if entry["status"] else entry["error"]
        sources = sorted(ctx.link_sources.get(url, []))
        for source in sources or [""]:
            findings.add(
                f"broken-{what}:{url}", f"Broken {'internal' if internal else 'external'} {what}: {short(url, 90)}",
                "medium" if internal else "low", source,
                description=f"A {what} on the site points to a URL that does not load.",
                expected="The URL returns a 2xx or 3xx response", actual=outcome, evidence=url,
                fix="Correct the URL, restore the missing file, or remove the reference.",
                confidence="high" if internal else "medium")

    # Requests the browser saw fail that static HTML does not reveal (fetch/XHR, scripts added at runtime).
    for page in ctx.pages:
        for failed in page.browser.get("failed_requests", []):
            url = failed["url"]
            if url in ctx.link_status or (failed["status"] or 0) >= 500:
                continue
            ctx.link_status[url] = {"status": failed["status"], "error": failed["error"], "state": "broken"}
            counts["resource"][0] += 1
            counts["resource"][1] += 1
            findings.add(
                f"broken-resource:{url}", f"Request fails at runtime: {short(url, 90)}", "medium", page.final_url,
                description=f"The page requested this {failed['type']} while loading and the request failed.",
                expected="The request succeeds", actual=f"HTTP {failed['status']}" if failed["status"] else failed["error"],
                evidence=url, fix="Fix the URL or the endpoint, or remove the request.")

    browser_pages = [p for p in ctx.html_pages if p.browser.get("loaded")]
    pages_with_errors = 0
    for page in browser_pages:
        errors = page.browser["page_errors"] + page.browser["console_errors"]
        if not errors:
            continue
        pages_with_errors += 1
        uncaught = bool(page.browser["page_errors"])
        findings.add(
            f"js-error:{short(errors[0], 80)}",
            f"{'Uncaught JavaScript exception' if uncaught else 'JavaScript console error'}: {short(errors[0], 80)}",
            "medium" if uncaught else "low", page.final_url,
            description="The page throws a JavaScript error while loading, so part of it may not work.",
            expected="The page loads without JavaScript errors", actual=short(errors[0], 300),
            evidence="\n".join(errors[:5]), fix="Open the page with the browser console and fix the error at its source.")

    # One pass rate per kind of test, averaged, so 500 healthy links cannot hide a broken page.
    rates, parts = [], []
    for kind, label in (("link", "links"), ("resource", "resources")):
        total, broken = counts[kind]
        if total:
            rates.append(pass_rate_score(total - broken, total))
            parts.append(f"{total - broken} of {total} {label} load")
    if browser_pages:
        rates.append(pass_rate_score(len(browser_pages) - pages_with_errors, len(browser_pages)))
        parts.append(f"{len(browser_pages) - pages_with_errors} of {len(browser_pages)} pages run without JavaScript errors")
    if not rates:
        return CheckResult("links_resources", CATEGORY, tested=False, reason="No links, resources or pages to test")

    score = sum(rates) / len(rates)
    # Split the points lost by each kind evenly over its failures, for the fix list.
    result_findings = findings.list()
    for f in result_findings:
        if f.rule.startswith("broken-link"):
            total, broken = counts["link"]
        elif f.rule.startswith("broken-resource"):
            total, broken = counts["resource"]
        else:
            total, broken = len(browser_pages), pages_with_errors
        kind_loss = (100.0 - pass_rate_score(total - broken, total)) / len(rates) if total else 0.0
        failures = f.occurrences if f.rule.startswith("js-error") else 1   # one JS error can break several pages
        f.loss = kind_loss * failures / broken if broken else 0.0

    summary = "; ".join(parts)
    if unverified:
        summary += f"; {unverified} URLs could not be verified"
    return CheckResult(
        "links_resources", CATEGORY, score=score, method="pass_rate", summary=summary, findings=result_findings,
        details={"links": counts["link"], "resources": counts["resource"], "unverified": unverified,
                 "pages_in_browser": len(browser_pages), "pages_with_js_errors": pages_with_errors})
