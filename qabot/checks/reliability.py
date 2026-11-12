"""Reliability and backend health, Phase 1: server errors in normal use and error handling."""
from __future__ import annotations

import re
import uuid

import requests

from ..models import CheckResult, FindingSet, ScanContext
from ..scoring import linear_score, pass_rate_score
from ..util import same_origin, short

CATEGORY = "reliability"

# Signs that an error page shows internals instead of a friendly message.
LEAK_PATTERNS = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("Java stack trace", re.compile(r"\bat [\w.$]+\([\w$]+\.java:\d+\)")),
    ("PHP error", re.compile(r"(Fatal error|Warning|Notice|Parse error)(</b>)?:\s.{0,300}? on line (<b>)?\d+", re.S)),
    (".NET exception", re.compile(r"System\.\w+Exception|Server Error in '/' Application")),
    ("Node.js stack trace", re.compile(r"\bat .+ \(.+\.js:\d+:\d+\)")),
    ("SQL error", re.compile(r"You have an error in your SQL syntax|ORA-\d{5}|SQLSTATE\[|psycopg2\.|sqlite3\.OperationalError")),
    ("framework debug page", re.compile(r"Werkzeug Debugger|DEBUG = True|Whitelabel Error Page|Symfony Exception")),
]


def run(ctx: ScanContext) -> list:
    return [error_rate(ctx), error_handling(ctx)]


def find_leak(text: str):
    for label, pattern in LEAK_PATTERNS:
        match = pattern.search(text or "")
        if match:
            return label, short(match.group(0), 160)
    return None


def error_rate(ctx: ScanContext) -> CheckResult:
    """Share of ordinary same-origin requests that ended in a 5xx, a timeout or a dropped connection."""
    findings = FindingSet(CATEGORY, "error_rate")
    seen, failures = {}, {}
    for entry in ctx.request_log:
        seen[entry["url"]] = entry
    # API calls and other requests the pages made in the browser count as normal use too.
    for page in ctx.pages:
        for failed in page.browser.get("failed_requests", []):
            if same_origin(failed["url"], ctx.origin) and (failed["status"] or 0) >= 500:
                seen[failed["url"]] = {"url": failed["url"], "status": failed["status"], "error": "", "via": page.final_url}
    for url, entry in seen.items():
        if entry["error"] or (entry["status"] or 0) >= 500:
            failures[url] = entry
    total = len(seen)
    if not total:
        return CheckResult("error_rate", CATEGORY, tested=False, reason="No requests were made")

    rate = 100.0 * len(failures) / total
    t = ctx.config["thresholds"]["error_rate_pct"]
    score = linear_score(rate, t["good"], t["poor"])
    for url, entry in failures.items():
        outcome = f"HTTP {entry['status']}" if entry["status"] else entry["error"]
        sources = sorted(ctx.link_sources.get(url, [])) or [entry.get("via", "")]
        f = findings.add(
            f"server-error:{url}", f"Server error on {short(url, 90)}", "high", url,
            description="The server failed on an ordinary request. Users see an error page or a broken feature.",
            expected="A 2xx, 3xx or 4xx response", actual=outcome,
            evidence=f"Requested from: {', '.join(s for s in sources[:3] if s) or 'direct request'}",
            fix="Check the server log for this request, fix the exception, and add a test for the case.")
        f.loss = (100.0 - score) / len(failures)
    return CheckResult(
        "error_rate", CATEGORY, score=score, method="measured",
        summary=f"{len(failures)} of {total} requests failed on the server side ({rate:.1f}%)",
        findings=findings.list(), details={"requests": total, "failures": len(failures), "error_rate_pct": round(rate, 2)})


def error_handling(ctx: ScanContext) -> CheckResult:
    """Four pass/fail tests on how the site behaves when something goes wrong."""
    findings = FindingSet(CATEGORY, "error_handling")
    tests = []   # (name, passed)

    def fetch(path: str):
        try:
            return ctx.http.get(ctx.origin + path, allow_redirects=True)
        except requests.RequestException:
            return None

    # 1 and 2: a page that does not exist
    missing = fetch(f"/qabot-missing-{uuid.uuid4().hex[:10]}")
    if missing is not None:
        ok = missing.status_code in (404, 410)
        tests.append(("Unknown URL returns 404", ok))
        if not ok:
            soft = missing.status_code < 400
            findings.add(
                "bad-404-status", "A page that does not exist does not return 404", "medium" if soft else "high", missing.url,
                description=("The server answers 200 for a missing page (a 'soft 404'), so search engines index error "
                             "pages and monitoring cannot see broken links." if soft else
                             "A missing page makes the server fail instead of answering 'not found'."),
                expected="HTTP 404", actual=f"HTTP {missing.status_code}",
                fix="Return status 404 with a friendly error page for unknown URLs.")
        leak = find_leak(missing.text)
        tests.append(("404 page shows no internals", leak is None))
        if leak:
            _leak_finding(findings, leak, missing.url)

    # 3: an abnormal request should be refused cleanly, not crash the server
    long_path = fetch("/" + "a" * 2000)
    if long_path is not None:
        ok = long_path.status_code < 500
        tests.append(("Over-long URL is refused without a server error", ok))
        if not ok:
            findings.add(
                "crash-on-long-url", "An over-long URL makes the server fail", "medium", ctx.origin + "/aaaa…(2,000 characters)",
                description="Unexpected input should be rejected with a 4xx response, not cause a 5xx.",
                expected="HTTP 404 or 414", actual=f"HTTP {long_path.status_code}",
                fix="Validate request input and return a 4xx response for requests the application cannot serve.",
                reference="OWASP A10:2025 Mishandling of Exceptional Conditions")

    # 4: no crawled page, whatever its status, shows a stack trace or debug output
    leaking = []
    for page in ctx.pages:
        leak = find_leak(page.html)
        if leak:
            leaking.append(page)
            _leak_finding(findings, leak, page.final_url)
    if ctx.pages:
        tests.append(("No page shows a stack trace or debug output", not leaking))

    if not tests:
        return CheckResult("error_handling", CATEGORY, tested=False, reason="The site did not answer the error-handling requests")
    passed = sum(1 for _, ok in tests if ok)
    score = pass_rate_score(passed, len(tests))
    found = findings.list()
    failed = len(tests) - passed
    for f in found:
        f.loss = (100.0 - score) / max(len(found), 1) if failed else 0.0
    return CheckResult(
        "error_handling", CATEGORY, score=score, method="pass_rate",
        summary=f"{passed} of {len(tests)} error-handling tests pass", findings=found,
        details={"tests": [{"name": name, "passed": ok} for name, ok in tests]})


def _leak_finding(findings: FindingSet, leak: tuple, location: str) -> None:
    label, sample = leak
    findings.add(
        "error-leak", "Error pages show internal details (stack trace or debug output)", "medium", location,
        description="Stack traces reveal file paths, library versions and code structure, and show that errors are not handled.",
        expected="A generic error page; details go to the server log only", actual=f"{label} in the response body",
        evidence=sample, fix="Turn off debug mode in production and add a global error handler that returns a generic page.",
        reference="OWASP A10:2025 Mishandling of Exceptional Conditions")
