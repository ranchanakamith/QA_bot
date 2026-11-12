"""Accessibility, Phase 1: a built-in WCAG A/AA rule scan and a keyboard walk-through.

The rules follow the names and impact levels of the matching axe-core rules.
Automated rules find only part of all accessibility problems; a manual review
is still needed.
"""
from __future__ import annotations

import re
from collections import Counter

from ..crawler import soup_of
from ..models import CheckResult, FindingSet, ScanContext
from ..scoring import findings_score, pass_rate_score
from ..util import short

CATEGORY = "accessibility"
IMPACT_TO_SEVERITY = {"critical": "critical", "serious": "high", "moderate": "medium", "minor": "low"}
UNLABELLED_INPUT_TYPES = {"hidden", "submit", "button", "reset", "image"}


def run(ctx: ScanContext) -> list:
    return [wcag_scan(ctx), keyboard(ctx)]


# ----------------------------------------------------------------- helpers ---
def _hidden(el) -> bool:
    return (el.has_attr("data-qabot-hidden") or el.has_attr("hidden") or el.get("aria-hidden") == "true"
            or "display:none" in (el.get("style") or "").replace(" ", "").lower())


def _has_name(el) -> bool:
    """Does the element have an accessible name from its text, ARIA, title or a labelled image inside?"""
    if (el.get("aria-label") or "").strip() or el.get("aria-labelledby") or (el.get("title") or "").strip():
        return True
    if el.get_text(strip=True):
        return True
    for img in el.find_all("img"):
        if (img.get("alt") or "").strip():
            return True
    for svg in el.find_all("svg"):
        if svg.find("title") or (svg.get("aria-label") or "").strip():
            return True
    return False


def _snippet(el) -> str:
    return short(str(el), 160)


# ------------------------------------------------------------------- rules ---
def scan_dom(html: str) -> list:
    """Returns [(rule, impact, snippet)] for one page."""
    soup = soup_of(html)
    issues = []
    add = lambda rule, impact, el=None: issues.append((rule, impact, _snippet(el) if el is not None else ""))

    root = soup.find("html")
    if root is None or not (root.get("lang") or "").strip():
        add("html-has-lang", "serious", None)
    if soup.title is None or not soup.title.get_text(strip=True):
        add("document-title", "serious", None)

    for img in soup.find_all("img"):
        if _hidden(img) or img.get("role") in ("presentation", "none"):
            continue
        if not img.has_attr("alt") and not (img.get("aria-label") or "").strip() and not img.get("aria-labelledby"):
            add("image-alt", "critical", img)

    labelled_ids = {lab.get("for") for lab in soup.find_all("label") if lab.get("for")}
    for field in soup.find_all(["input", "select", "textarea"]):
        if _hidden(field) or (field.name == "input" and (field.get("type") or "text").lower() in UNLABELLED_INPUT_TYPES):
            continue
        named = ((field.get("aria-label") or "").strip() or field.get("aria-labelledby")
                 or (field.get("title") or "").strip() or field.get("id") in labelled_ids
                 or field.find_parent("label") is not None)
        if not named:
            add("label", "critical", field)

    for button in soup.find_all("button"):
        if not _hidden(button) and not _has_name(button):
            add("button-name", "critical", button)
    for button in soup.find_all("input", type=lambda t: (t or "").lower() in ("button", "image")):
        if not _hidden(button) and not ((button.get("value") or "").strip() or (button.get("alt") or "").strip()
                                        or (button.get("aria-label") or "").strip()):
            add("button-name", "critical", button)

    for link in soup.find_all("a", href=True):
        if not _hidden(link) and not _has_name(link):
            add("link-name", "serious", link)

    for frame in soup.find_all("iframe"):
        if not _hidden(frame) and not (frame.get("title") or "").strip() and not (frame.get("aria-label") or "").strip():
            add("frame-title", "serious", frame)

    viewport = soup.find("meta", attrs={"name": "viewport"})
    if viewport is not None:
        content = (viewport.get("content") or "").lower().replace(" ", "")
        max_scale = re.search(r"maximum-scale=([\d.]+)", content)
        if "user-scalable=no" in content or "user-scalable=0" in content or (max_scale and float(max_scale.group(1)) < 2):
            add("meta-viewport", "critical", viewport)

    previous = 0
    for heading in soup.find_all(re.compile(r"^h[1-6]$")):
        if _hidden(heading):
            continue
        level = int(heading.name[1])
        if not _has_name(heading):
            add("empty-heading", "minor", heading)
        if previous and level > previous + 1:
            add("heading-order", "moderate", heading)
        previous = level

    ids = Counter(el["id"] for el in soup.find_all(id=True) if el["id"].strip())
    for value, count in ids.items():
        if count > 1:
            add("duplicate-id", "minor", soup.find(id=value))
    return issues


RULES = {
    "html-has-lang": ("The page does not declare its language", "WCAG 3.1.1",
                      "Screen readers need the language to pronounce the text correctly.",
                      "Add a lang attribute to the <html> element, for example <html lang=\"en\">."),
    "document-title": ("The page has no title", "WCAG 2.4.2",
                       "The title is the first thing a screen reader announces and what tabs and bookmarks show.",
                       "Add a short, unique <title> to every page."),
    "image-alt": ("Images have no alternative text", "WCAG 1.1.1",
                  "Screen-reader users get no information from an image without alt text.",
                  "Add alt text that describes the image, or alt=\"\" when it is purely decorative."),
    "label": ("Form fields have no label", "WCAG 4.1.2",
              "Without a label, screen-reader users cannot tell what to type. A placeholder is not a label.",
              "Connect a <label for=…> to each field, or add aria-label."),
    "button-name": ("Buttons have no accessible name", "WCAG 4.1.2",
                    "A button with only an icon is announced as just 'button'.",
                    "Add visible text, or an aria-label, to the button."),
    "link-name": ("Links have no accessible name", "WCAG 2.4.4",
                  "A link with no text is announced as just 'link', so its purpose is unknown.",
                  "Add link text, or alt text on the image inside the link."),
    "frame-title": ("Frames have no title", "WCAG 4.1.2",
                    "Screen-reader users cannot tell what an untitled frame contains.",
                    "Add a title attribute to each <iframe>."),
    "meta-viewport": ("Zooming is disabled", "WCAG 1.4.4",
                      "People with low vision must be able to zoom the page.",
                      "Remove user-scalable=no and maximum-scale from the viewport meta tag."),
    "color-contrast": ("Text does not have enough contrast with its background", "WCAG 1.4.3",
                       "Low-contrast text is hard to read for people with low vision and for everyone in bright light.",
                       "Darken the text or lighten the background until the ratio reaches 4.5:1 (3:1 for large text)."),
    "heading-order": ("Heading levels are skipped", "Best practice",
                      "Screen-reader users navigate by headings; a jump from h2 to h4 hides the structure.",
                      "Use heading levels in order without skipping."),
    "empty-heading": ("Headings are empty", "Best practice",
                      "An empty heading is announced but says nothing.",
                      "Remove empty headings or give them text."),
    "duplicate-id": ("The same id is used more than once", "Best practice",
                     "Labels and ARIA references that point to a duplicated id may attach to the wrong element.",
                     "Make every id unique within the page."),
}
PAGE_LEVEL_RULES = {"html-has-lang", "document-title"}
IMPACTS = {"html-has-lang": "serious", "document-title": "serious", "image-alt": "critical", "label": "critical",
           "button-name": "critical", "link-name": "serious", "frame-title": "serious", "meta-viewport": "critical",
           "color-contrast": "serious", "heading-order": "moderate", "empty-heading": "minor", "duplicate-id": "minor"}


def wcag_scan(ctx: ScanContext) -> CheckResult:
    pages = ctx.html_pages
    if not pages:
        return CheckResult("wcag_scan", CATEGORY, tested=False, reason="No HTML page loaded")
    findings = FindingSet(CATEGORY, "wcag_scan")
    rules_run = len(RULES) - (0 if ctx.browser is not None else 1)

    def report(rule: str, location: str, evidence: str, actual: str) -> None:
        title, reference, description, fix = RULES[rule]
        finding = findings.add(
            rule, title, IMPACT_TO_SEVERITY[IMPACTS[rule]], location, description=description,
            expected="No violations of this rule", actual=actual, evidence=evidence, fix=fix, reference=reference,
            confidence="high" if ctx.browser is not None else "medium")
        return finding

    elements = Counter()
    for page in pages:
        per_rule = Counter()
        first = {}
        for rule, _impact, snippet in scan_dom(page.dom):
            per_rule[rule] += 1
            first.setdefault(rule, snippet)
        for rule, count in per_rule.items():
            elements[rule] += count
            finding = report(rule, page.final_url, first[rule], "")
            where = f"{finding.occurrences} page{'s' if finding.occurrences != 1 else ''}"
            finding.actual = (f"Missing on {where}" if rule in PAGE_LEVEL_RULES else
                              f"{elements[rule]} element{'s' if elements[rule] != 1 else ''} on {where}")
        contrast = page.browser.get("contrast")
        if contrast and contrast["failed"]:
            worst = min(contrast["failures"], key=lambda f: f["ratio"])
            report("color-contrast", page.final_url,
                   f"\"{worst['text']}\" has ratio {worst['ratio']}:1 ({worst['fg']} on {worst['bg']}); "
                   f"needs {worst['required']}:1",
                   f"{contrast['failed']} of {contrast['checked']} text elements on this page")

    found = findings.list()
    scope = f"{rules_run} built-in rules on {len(pages)} page{'s' if len(pages) != 1 else ''}"
    if ctx.browser is None:
        scope += " (contrast needs a browser and was skipped)"
    return CheckResult(
        "wcag_scan", CATEGORY, score=findings_score(found, ctx.config["deductions"]), method="findings",
        summary=f"{len(found)} rule{'s' if len(found) != 1 else ''} violated; {scope}. "
                "Automated rules catch only part of all accessibility problems.",
        findings=found, details={"rules_run": rules_run, "pages": len(pages)})


# ---------------------------------------------------------------- keyboard ---
def keyboard(ctx: ScanContext) -> CheckResult:
    if ctx.browser is None:
        return CheckResult("keyboard", CATEGORY, tested=False)
    pages = sorted(ctx.html_pages, key=lambda p: p.depth)[: ctx.config["accessibility"]["keyboard_sample_pages"]]
    findings = FindingSet(CATEGORY, "keyboard")
    passed = total = 0
    failed_rules = Counter()

    def test(ok: bool, rule: str, title: str, severity: str, location: str, **fields) -> None:
        nonlocal passed, total
        total += 1
        if ok:
            passed += 1
        else:
            failed_rules[rule] += 1
            findings.add(rule, title, severity, location, **fields)

    for page in pages:
        r = ctx.browser.keyboard_check(page.final_url)
        if "error" in r:
            continue
        url = page.final_url
        test(r["positiveTabindex"] == 0, "positive-tabindex", "Positive tabindex changes the natural tab order", "low", url,
             description="tabindex values above 0 pull elements out of the reading order, which disorients keyboard users.",
             expected="No tabindex greater than 0", actual=f"{r['positiveTabindex']} elements", reference="WCAG 2.4.3",
             fix="Remove positive tabindex values and order the elements in the HTML instead.")
        test(r["clickOnly"] == 0, "click-without-keyboard", "Clickable elements cannot be used with the keyboard", "high", url,
             description="An element with a click handler that is not a link or button and has no tabindex cannot be reached with Tab.",
             expected="Clickable elements are links or buttons", actual=f"{r['clickOnly']} elements",
             evidence=r["clickOnlySample"], reference="WCAG 2.1.1",
             fix="Use a <button> or <a>, or add tabindex=\"0\", a role and a key handler.")
        if r["expected"]:
            test(r["reached"] >= 0.9 * r["expected"], "tab-unreachable", "Tab does not reach every interactive element", "high", url,
                 description="Some links, buttons or fields are skipped when moving through the page with the Tab key.",
                 expected=f"Tab reaches all {r['expected']} interactive elements", actual=f"Reached {r['reached']}",
                 reference="WCAG 2.1.1", fix="Check for focus traps and for scripts that move or block focus.")
            test(r["without_indicator"] <= 0.1 * max(r["reached"], 1), "focus-not-visible",
                 "Focused elements show no visible focus indicator", "high", url,
                 description="Keyboard users cannot see where they are on the page when the focus outline is removed.",
                 expected="Every focused element shows an outline or another visible change",
                 actual=f"{r['without_indicator']} of {r['reached']} focused elements show no change",
                 evidence=r["indicator_sample"], reference="WCAG 2.4.7",
                 fix="Do not remove outlines (outline: none) without providing a :focus-visible style.")

    if not total:
        return CheckResult("keyboard", CATEGORY, tested=False, reason="No page could be loaded for the keyboard test")
    score = pass_rate_score(passed, total)
    found = findings.list()
    for f in found:
        f.loss = 100.0 * failed_rules[f.rule] / total
    return CheckResult("keyboard", CATEGORY, score=score, method="pass_rate",
                       summary=f"{passed} of {total} keyboard tests pass on {len(pages)} page{'s' if len(pages) != 1 else ''}",
                       findings=found, details={"passed": passed, "total": total})
