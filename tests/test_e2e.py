"""End-to-end: scan the demo site with planted defects, then the clean version.

The bot must find what was planted, and must not invent problems on the clean site.
"""
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo_site.server import make_server  # noqa: E402
from qabot.config import load_config  # noqa: E402
from qabot.report import render_html, write_reports  # noqa: E402
from qabot.scan import compare, run_scan  # noqa: E402


def scan(good: bool, **overrides) -> dict:
    server = make_server(port=0, good=good)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cfg = load_config(overrides={"crawl": {"check_external": False, "requests_per_second": 50}, **overrides})
        return run_scan(f"http://127.0.0.1:{server.server_address[1]}", cfg, owned=True, log=lambda *_: None)
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="module")
def bad():
    return scan(good=False)


@pytest.fixture(scope="module")
def good():
    return scan(good=True)


def rules(report: dict) -> set:
    return {f["rule"].split(":")[0] for f in report["findings"]}


def category(report: dict, cat_id: str) -> dict:
    return next(c for c in report["score"]["categories"] if c["id"] == cat_id)


# ------------------------------------------------------- site with defects ---
def test_finds_planted_defects_without_a_browser_too(bad):
    found = rules(bad)
    expected = {
        "exposed-env", "exposed-git", "password-in-url",                       # security: passive scan and probes
        "missing-csp", "missing-clickjacking-protection", "missing-nosniff",   # security: headers
        "version-disclosure-server", "version-disclosure-x-powered-by",
        "cookie-no-httponly-session", "cookie-no-samesite",                    # security: cookies
        "broken-link", "broken-resource",                                      # functional
        "server-error", "error-leak",                                          # reliability
        "html-has-lang", "document-title", "image-alt", "label", "button-name", "heading-order",  # accessibility
    }
    assert expected <= found, f"missed: {sorted(expected - found)}"


def test_finds_browser_only_defects(bad):
    if not bad["browser"]:
        pytest.skip("no browser available")
    expected = {"js-error", "color-contrast", "focus-not-visible", "click-without-keyboard",
                "no-viewport-meta", "overflow-desktop", "overflow-tablet", "overflow-phone"}
    assert expected <= rules(bad), f"missed: {sorted(expected - rules(bad))}"
    api = [f for f in bad["findings"] if f["rule"].endswith("/api/stock")]
    assert api and api[0]["check"] == "error_rate"     # a failing backend call made by the page


def test_critical_security_finding_caps_the_score(bad):
    score = bad["score"]
    assert score["score"] == 39 and score["level"] == 1 and score["capped"]
    assert score["gates"][0]["id"] == "security_critical"
    assert bad["fix_list"][0] == next(f["id"] for f in bad["findings"] if f["rule"] == "exposed-env")


def test_untested_checks_are_reported_not_scored(bad):
    assert category(bad, "maintainability")["tested"] is False
    assert bad["score"]["weight_tested"] == 90
    names = {n["check"] for n in bad["not_tested"]}
    assert {"Load test", "Critical user flows", "Test coverage"} <= names


def test_local_target_gets_no_https_findings(bad):
    assert not {"no-https", "password-over-http", "missing-hsts"} & rules(bad)


def test_same_issue_on_many_pages_is_one_finding(bad):
    csp = [f for f in bad["findings"] if f["rule"] == "missing-csp"]
    assert len(csp) == 1 and csp[0]["occurrences"] >= 4


# -------------------------------------------------------------- clean site ---
def test_clean_site_has_no_false_positives(good):
    real = [f for f in good["findings"] if f["severity"] != "info"]
    assert real == [], [(f["rule"], f["actual"]) for f in real]
    assert good["score"]["score"] >= 95 and good["score"]["level"] == 5 and not good["score"]["capped"]


# ------------------------------------------------------------------ extras ---
def test_smoke_failure_stops_the_scan():
    report = run_scan("http://127.0.0.1:9", load_config(overrides={"crawl": {"timeout_seconds": 3}}), log=lambda *_: None)
    assert report["smoke"]["passed"] is False
    assert report["score"]["score"] == 0 and report["findings"] == []
    assert "Smoke test failed" in render_html(report) or "smoke test" in render_html(report)


def test_reports_are_written_and_baseline_compares(bad, good, tmp_path):
    compare(good, bad)
    assert good["baseline"]["delta"] == good["score"]["score"] - bad["score"]["score"]
    assert "exposed-env" in good["baseline"]["fixed"]
    paths = write_reports(good, tmp_path)
    html = paths["html"].read_text(encoding="utf-8")
    assert "Level 5" in html and "Previous run" in html
    assert paths["json"].exists()


def test_scan_without_browser_still_scores():
    report = scan(good=False, browser={"enabled": False})
    assert report["browser"] == ""
    assert category(report, "compatibility")["tested"] is False
    assert category(report, "accessibility")["tested"] is True
    assert report["check_details"]["page_speed"]["mode"] == "http"
    render_html(report)
