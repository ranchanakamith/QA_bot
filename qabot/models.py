"""Data structures shared by the crawler, the checks, the scorer and the report."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    rule: str                      # stable rule id; the same rule on many pages is one finding
    title: str
    severity: str                  # critical | high | medium | low | info
    category: str = ""
    check: str = ""
    locations: list = field(default_factory=list)
    occurrences: int = 0
    description: str = ""
    expected: str = ""
    actual: str = ""
    evidence: str = ""
    fix: str = ""
    reference: str = ""            # e.g. "OWASP A02:2025" or "WCAG 1.1.1"
    confidence: str = "high"
    loss: float | None = None      # points this finding costs its check (0-100); set by the check or the scorer
    impact_points: float = 0.0     # points it costs the overall score (before gates)
    gate: str = ""                 # set when this finding triggers a score cap
    id: str = ""                   # QA-001, assigned when the report is built


class FindingSet:
    """Collects findings for one check and merges repeats of the same rule."""

    MAX_LOCATIONS = 10

    def __init__(self, category: str, check: str):
        self.category = category
        self.check = check
        self._by_rule: dict[str, Finding] = {}

    def add(self, rule: str, title: str, severity: str, location: str = "", **fields: Any) -> Finding:
        finding = self._by_rule.get(rule)
        if finding is None:
            finding = Finding(rule=rule, title=title, severity=severity,
                              category=self.category, check=self.check, **fields)
            self._by_rule[rule] = finding
        finding.occurrences += 1
        if location and location not in finding.locations and len(finding.locations) < self.MAX_LOCATIONS:
            finding.locations.append(location)
        return finding

    def list(self) -> list:
        return list(self._by_rule.values())

    def __len__(self) -> int:
        return len(self._by_rule)


@dataclass
class CheckResult:
    id: str
    category: str
    tested: bool = True
    score: float | None = None     # 0-100 when tested
    method: str = ""               # pass_rate | measured | findings
    summary: str = ""
    reason: str = ""               # why it was not tested
    details: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)


@dataclass
class Page:
    url: str
    depth: int = 0
    referrer: str | None = None
    final_url: str = ""
    status: int | None = None
    error: str = ""                # network-level failure, if any
    headers: Any = field(default_factory=dict)
    set_cookies: list = field(default_factory=list)   # raw Set-Cookie header values
    redirects: list = field(default_factory=list)
    content_type: str = ""
    elapsed_ms: float = 0.0        # time to response headers (approximates TTFB)
    size_bytes: int = 0
    html: str = ""                 # HTML as served
    links: list = field(default_factory=list)         # [(absolute_url, link_text)]
    resources: list = field(default_factory=list)     # [(kind, absolute_url)]
    forms: list = field(default_factory=list)
    browser: dict = field(default_factory=dict)       # filled when a browser visited the page

    @property
    def is_html(self) -> bool:
        return bool(self.html)

    @property
    def dom(self) -> str:
        """Rendered HTML when a browser loaded the page, else the HTML as served."""
        return self.browser.get("rendered_html") or self.html


@dataclass
class ScanContext:
    target: str
    origin: str
    config: dict
    owned: bool = False            # user confirmed they own the site
    is_local: bool = False
    http: Any = None
    browser: Any = None
    pages: list = field(default_factory=list)
    link_sources: dict = field(default_factory=dict)  # url -> set of pages that reference it
    link_kinds: dict = field(default_factory=dict)    # url -> "link" | "resource"
    link_status: dict = field(default_factory=dict)   # url -> {"status", "error", "state"}
    request_log: list = field(default_factory=list)   # same-origin requests: {"url","status","error","ms"}
    skipped_by_robots: list = field(default_factory=list)
    tls_error: str = ""
    redirected_from: str = ""     # original origin when the start URL redirected elsewhere
    notes: list = field(default_factory=list)
    screenshots: dict = field(default_factory=dict)   # viewport -> base64 JPEG

    @property
    def html_pages(self) -> list:
        return [p for p in self.pages if p.is_html and p.status and p.status < 400]

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)
