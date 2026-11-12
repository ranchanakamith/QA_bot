"""Performance, Phase 1: page speed in the lab. Load, stress, spike and soak tests come in Phase 3."""
from __future__ import annotations

from ..models import CheckResult, FindingSet, ScanContext
from ..scoring import linear_score

CATEGORY = "performance"
METRICS = ("tbt_ms", "lcp_ms", "cls", "fcp_ms")
FIXES = {
    "lcp_ms": "Make the largest element load sooner: compress and size the hero image, preload it, and cut render-blocking CSS and JS.",
    "cls": "Reserve space for images, ads and embeds (width/height or aspect-ratio) so content does not jump.",
    "tbt_ms": "Break up long JavaScript tasks, defer scripts that are not needed for first paint, and remove unused code.",
    "fcp_ms": "Reduce server response time and render-blocking resources so the first content paints sooner.",
    "ttfb_ms": "Speed up the server response: cache pages, optimise slow queries, and serve from a location near users.",
}


def run(ctx: ScanContext) -> list:
    return [page_speed(ctx)]


def _fmt(metric: str, value: float) -> str:
    return f"{value:.2f}" if metric == "cls" else f"{value:,.0f} ms"


def sample_pages(ctx: ScanContext, count: int) -> list:
    """The start page first, then the shallowest pages."""
    return sorted(ctx.html_pages, key=lambda p: (p.depth, ctx.pages.index(p)))[:count]


def page_speed(ctx: ScanContext) -> CheckResult:
    cfg = ctx.config
    thresholds = cfg["thresholds"]
    findings = FindingSet(CATEGORY, "page_speed")
    pages = sample_pages(ctx, cfg["performance"]["sample_pages"])
    if not pages:
        return CheckResult("page_speed", CATEGORY, tested=False, reason="No HTML page loaded")

    rows = []
    if ctx.browser is not None:
        total_weight = sum(thresholds[m]["weight"] for m in METRICS)
        for page in pages:
            measured = ctx.browser.measure(page.final_url)
            if "error" in measured:
                ctx.note(f"Performance could not be measured on {page.final_url}: {measured['error']}")
                continue
            row = {"url": page.final_url, "metrics": {}, "requests": measured["requests"],
                   "transfer_bytes": measured["transfer_bytes"], "ttfb_ms": round(measured["ttfb_ms"])}
            score = 0.0
            for metric in METRICS:
                t = thresholds[metric]
                metric_score = linear_score(measured[metric], t["good"], t["poor"])
                row["metrics"][metric] = {"value": round(measured[metric], 3), "score": round(metric_score)}
                score += metric_score * t["weight"] / total_weight
            row["score"] = round(score, 1)
            rows.append(row)
        if rows:
            # One finding per metric that is below "good" somewhere, located on the pages where it is.
            for metric in METRICS:
                t = thresholds[metric]
                slow = [r for r in rows if r["metrics"][metric]["score"] < 100]
                if not slow:
                    continue
                worst = max(slow, key=lambda r: r["metrics"][metric]["value"])
                poor = worst["metrics"][metric]["score"] == 0
                lost = sum(100 - r["metrics"][metric]["score"] for r in rows) / len(rows) * t["weight"] / total_weight
                for r in slow:
                    f = findings.add(
                        f"slow-{metric}", f"{t['label']} is {'poor' if poor else 'slower than the good threshold'}",
                        "medium" if poor else "low", r["url"],
                        description=f"{t['label']} is one of the page-speed metrics users feel directly.",
                        expected=f"{_fmt(metric, t['good'])} or less",
                        actual=f"{_fmt(metric, worst['metrics'][metric]['value'])} on the slowest page",
                        evidence=worst["url"], fix=FIXES[metric])
                    f.loss = lost
            score = sum(r["score"] for r in rows) / len(rows)
            throttle = cfg["performance"]["throttle"]
            mode = ("phone viewport, throttled to a mid-range phone on a slow 4G connection"
                    if throttle == "mobile" else "phone viewport, no throttling")
            slowest = min(rows, key=lambda r: r["score"])
            summary = (f"Lab run on {len(rows)} page{'s' if len(rows) != 1 else ''} ({mode}); "
                       f"slowest page scores {slowest['score']:.0f}. Uses the Lighthouse metric weights without Speed Index.")
            _hints(ctx, pages, findings, {r["url"]: r["transfer_bytes"] for r in rows})
            return CheckResult("page_speed", CATEGORY, score=score, method="measured", summary=summary,
                               findings=findings.list(), details={"mode": "browser", "throttle": throttle, "pages": rows})

    # No browser: server response time is the only speed signal available.
    t = thresholds["ttfb_ms"]
    for page in pages:
        metric_score = linear_score(page.elapsed_ms, t["good"], t["poor"])
        rows.append({"url": page.final_url, "ttfb_ms": round(page.elapsed_ms), "score": round(metric_score, 1),
                     "transfer_bytes": page.size_bytes})
    slow = [r for r in rows if r["score"] < 100]
    lost = sum(100 - r["score"] for r in rows) / len(rows)
    for r in slow:
        worst = max(slow, key=lambda x: x["ttfb_ms"])
        f = findings.add(
            "slow-ttfb_ms", "Server response time is slower than the good threshold",
            "medium" if worst["score"] == 0 else "low", r["url"],
            description="Time to first byte is how long the server takes to start answering.",
            expected=f"{t['good']:,} ms or less", actual=f"{worst['ttfb_ms']:,} ms on the slowest page",
            evidence=worst["url"], fix=FIXES["ttfb_ms"])
        f.loss = lost
    _hints(ctx, pages, findings, {})
    return CheckResult(
        "page_speed", CATEGORY, score=sum(r["score"] for r in rows) / len(rows), method="measured",
        summary=f"Server response time only, on {len(rows)} pages: no browser was available for paint and layout metrics.",
        findings=findings.list(), details={"mode": "http", "pages": rows})


def _hints(ctx: ScanContext, pages: list, findings: FindingSet, transfer_bytes: dict) -> None:
    """Improvement hints that do not change the score (severity info)."""
    heavy = ctx.config["performance"]["heavy_page_bytes"]
    for page in pages:
        if page.size_bytes > 2048 and not page.headers.get("Content-Encoding"):
            findings.add(
                "no-compression", "HTML is served without compression", "info", page.final_url,
                description="Text responses compress to a fraction of their size with gzip or Brotli.",
                expected="Content-Encoding: br or gzip", actual="No Content-Encoding header",
                fix="Enable gzip or Brotli for text responses in the web server.")
        transfer = transfer_bytes.get(page.final_url, 0)
        if transfer > heavy:
            findings.add(
                "heavy-page", "The page downloads more than 3 MB", "info", page.final_url,
                description="Heavy pages are slow and costly on mobile connections.",
                expected=f"Under {heavy / 1e6:.0f} MB", actual=f"{transfer / 1e6:.1f} MB",
                fix="Compress and resize images, and load below-the-fold media lazily.")
