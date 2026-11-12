"""Browser and device compatibility: viewport sizes, and other browser engines when installed."""
from __future__ import annotations

from ..models import CheckResult, FindingSet, ScanContext
from ..scoring import pass_rate_score
from ..util import short

CATEGORY = "compatibility"
OVERFLOW_TOLERANCE_PX = 5


def run(ctx: ScanContext) -> list:
    if ctx.browser is None:
        return [CheckResult("viewports", CATEGORY, tested=False),
                CheckResult("cross_browser", CATEGORY, tested=False, reason="Needs a browser (Playwright)")]
    pages = sorted(ctx.html_pages, key=lambda p: p.depth)[: ctx.config["compatibility"]["sample_pages"]]
    return [viewports(ctx, pages), cross_browser(ctx, pages)]


def viewports(ctx: ScanContext, pages: list) -> CheckResult:
    findings = FindingSet(CATEGORY, "viewports")
    sizes = ctx.config["browser"]["viewports"]
    passed = total = 0
    failures = {}

    def test(ok: bool, rule: str, title: str, location: str, **fields) -> None:
        nonlocal passed, total
        total += 1
        if ok:
            passed += 1
        else:
            failures[rule] = failures.get(rule, 0) + 1
            findings.add(rule, title, "medium", location, **fields)

    for index, page in enumerate(pages):
        for name, size in sizes.items():
            first = index == 0
            if name == "desktop" and not first and page.browser.get("overflow"):
                result = page.browser["overflow"]          # already measured during the crawl
            else:
                result = ctx.browser.viewport_check(page.final_url, name, screenshot=first)
            if "error" in result:
                continue
            if "screenshot" in result:
                ctx.screenshots[name] = result.pop("screenshot")
            extra = result["scrollWidth"] - result["innerWidth"]
            test(extra <= OVERFLOW_TOLERANCE_PX, f"overflow-{name}",
                 f"The page is wider than the {name} screen and scrolls sideways", page.final_url,
                 description="Content that overflows the screen forces horizontal scrolling and often hides part of the page.",
                 expected=f"Content fits within the {result['innerWidth']} px layout width",
                 actual=f"Content is {result['scrollWidth']} px wide",
                 fix="Use relative widths and max-width: 100% on images and tables, and check fixed-width elements.",
                 reference="WCAG 1.4.10")
            if name == "phone":
                test("width=device-width" in result["viewportMeta"].replace(" ", ""), "no-viewport-meta",
                     "No responsive viewport meta tag", page.final_url,
                     description="Without it, phones render the page at desktop width and shrink it until text is unreadable.",
                     expected='<meta name="viewport" content="width=device-width, initial-scale=1">',
                     actual=short(result["viewportMeta"], 100) or "Tag absent",
                     fix="Add the viewport meta tag to the <head> of every page.")

    if not total:
        return CheckResult("viewports", CATEGORY, tested=False, reason="No page could be loaded in the browser")
    found = findings.list()
    for f in found:
        f.loss = 100.0 * failures[f.rule] / total
    return CheckResult("viewports", CATEGORY, score=pass_rate_score(passed, total), method="pass_rate",
                       summary=f"{passed} of {total} layout tests pass across {', '.join(sizes)} on "
                               f"{len(pages)} page{'s' if len(pages) != 1 else ''}",
                       findings=found, details={"passed": passed, "total": total})


def cross_browser(ctx: ScanContext, pages: list) -> CheckResult:
    engines, missing = ctx.browser.other_engines()
    if not engines:
        return CheckResult("cross_browser", CATEGORY, tested=False,
                           reason=f"Only Chromium is installed. Run: playwright install {' '.join(missing)}")
    findings = FindingSet(CATEGORY, "cross_browser")
    passed = total = 0
    failures = {}
    try:
        for name, engine in engines.items():
            for page in pages:
                record = ctx.browser.engine_check(engine, page.final_url)
                total += 1
                # Fails only on problems Chromium did not have on the same page.
                new_errors = [e for e in record["page_errors"] if e not in page.browser.get("page_errors", [])]
                problem = record.get("load_error") or (new_errors[0] if new_errors else "")
                if not problem and record.get("text_length") == 0:
                    problem = "The page renders no text"
                if not problem:
                    passed += 1
                    continue
                rule = f"fails-in-{name}"
                failures[rule] = failures.get(rule, 0) + 1
                findings.add(rule, f"Pages fail in {name.capitalize()} but work in Chromium", "medium", page.final_url,
                             description="The page loads cleanly in Chromium but not in this browser engine.",
                             expected="The page loads without errors in every supported browser",
                             actual=short(problem, 200), evidence=short(problem, 300),
                             fix="Open the page in that browser's developer tools and replace or polyfill the unsupported feature.")
    finally:
        for engine in engines.values():
            engine.close()
    found = findings.list()
    for f in found:
        f.loss = 100.0 * failures[f.rule] / total
    summary = f"{passed} of {total} page loads pass in {', '.join(engines)}"
    if missing:
        summary += f" ({', '.join(missing)} not installed)"
    return CheckResult("cross_browser", CATEGORY, score=pass_rate_score(passed, total), method="pass_rate",
                       summary=summary, findings=found, details={"engines": list(engines), "missing": missing})
