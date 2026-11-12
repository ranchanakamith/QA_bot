"""The scoring engine must reproduce the numbers in the design spec."""
import pytest

from qabot.config import load_config
from qabot.models import CheckResult, Finding
from qabot.scoring import compute, evaluate_gates, findings_score, level_for, linear_score, pass_rate_score


@pytest.fixture(scope="module")
def cfg():
    return load_config()


def result(check_id, category, score, findings=()):
    return CheckResult(check_id, category, score=score, method="findings", findings=list(findings))


def spec_example(cfg, security_findings=()):
    """The spec's worked example: a URL-only scan, code quality not tested."""
    return [
        result("links_resources", "functional", 88),
        result("tls_headers", "security", 70, security_findings),
        result("page_speed", "performance", 76),
        result("error_rate", "reliability", 90),
        result("wcag_scan", "accessibility", 64),
        result("viewports", "compatibility", 95),
    ]


def test_profiles_sum_to_100(cfg):
    for weights in cfg["profiles"].values():
        assert sum(weights.values()) == 100


def test_pass_rate_rule():
    assert pass_rate_score(18, 20) == 90


def test_measured_rule_matches_spec_example():
    # 95th-percentile response of 1,100 ms between 500 ms (good) and 2,000 ms (poor) scores 60
    assert linear_score(1100, 500, 2000) == pytest.approx(60)
    assert linear_score(400, 500, 2000) == 100
    assert linear_score(2500, 500, 2000) == 0


def test_measured_rule_higher_is_better():
    # breaking point: good at 2x expected peak, poor at 1x
    assert linear_score(1.5, 2.0, 1.0) == pytest.approx(50)


def test_findings_rule_matches_spec_example(cfg):
    found = [Finding("a", "", "high")] + [Finding(f"m{i}", "", "medium") for i in range(2)] \
        + [Finding(f"l{i}", "", "low") for i in range(3)]
    assert findings_score(found, cfg["deductions"]) == 58
    assert findings_score([Finding(str(i), "", "critical") for i in range(4)], cfg["deductions"]) == 0


def test_worked_example_without_gate(cfg):
    card = compute(spec_example(cfg), cfg, "general")
    assert card["score"] == 80            # 7,205 / 90
    assert card["weight_tested"] == 90
    assert card["level"] == 4
    assert not card["capped"]


def test_worked_example_with_high_security_finding(cfg):
    card = compute(spec_example(cfg, [Finding("x", "A high finding", "high")]), cfg, "general")
    assert card["raw_score"] == 80
    assert card["score"] == 74
    assert card["level"] == 3
    assert card["capped"] and card["gates"][0]["id"] == "security_high"


def test_critical_security_finding_caps_at_39(cfg):
    card = compute(spec_example(cfg, [Finding("x", "", "critical"), Finding("y", "", "high")]), cfg, "general")
    assert card["score"] == 39 and card["level"] == 1


def test_high_finding_outside_security_does_not_gate(cfg):
    results = spec_example(cfg)
    results[4].findings.append(Finding("contrast", "", "high"))
    assert evaluate_gates(results, cfg, smoke_failed=False) == []


def test_smoke_failure_scores_zero(cfg):
    card = compute([], cfg, "general", smoke_failed=True)
    assert card["score"] == 0 and card["level"] == 1


def test_untested_check_share_is_redistributed(cfg):
    card = compute([result("page_speed", "performance", 80)], cfg, "general")
    perf = next(c for c in card["categories"] if c["id"] == "performance")
    assert perf["score"] == 80            # the only tested check carries the whole category
    assert card["weight_tested"] == 15 and card["depth_tested"] == pytest.approx(15 * 0.35, abs=0.06)
    assert card["score"] == 80


@pytest.mark.parametrize("score,level", [(100, 5), (90, 5), (89, 4), (75, 4), (74, 3), (60, 3), (59, 2), (40, 2), (39, 1), (0, 1)])
def test_levels(cfg, score, level):
    assert level_for(score, cfg["levels"])["level"] == level
