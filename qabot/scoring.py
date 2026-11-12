"""The scoring model from the design spec.

    overall = min( sum(w_i * s_i) / sum(w_i)  over tested categories,  every gate cap that applies )

A check that could not run is left out and its share goes to the other checks in
its category; a category with no tested check is left out and its weight goes to
the other categories.
"""
from __future__ import annotations

from .models import SEVERITY_ORDER, CheckResult


# ------------------------------------------------- the three scoring rules ---
def pass_rate_score(passed: int, total: int) -> float:
    """Pass or fail tests: passed / total * 100."""
    return 100.0 if total <= 0 else 100.0 * passed / total


def linear_score(value: float, good: float, poor: float) -> float:
    """Measured values: 100 at the good threshold, 0 at the poor one, a straight line between.
    Works for lower-is-better (good < poor) and higher-is-better (good > poor) metrics."""
    if good == poor:
        return 100.0 if value <= good else 0.0
    score = 100.0 * (poor - value) / (poor - good)
    return max(0.0, min(100.0, score))


def findings_score(findings: list, deductions: dict) -> float:
    """Findings: start at 100 and subtract per distinct issue; never below 0."""
    return max(0.0, 100.0 - sum(deductions.get(f.severity, 0) for f in findings))


def level_for(score: float, levels: list) -> dict:
    for level in levels:
        if score >= level["min"]:
            return level
    return levels[-1]


# ------------------------------------------------------------------ gates ---
def _security_findings(results: list, severity: str) -> list:
    return [f for r in results if r.category == "security" and r.tested
            for f in r.findings if f.severity == severity]


def evaluate_gates(results: list, cfg: dict, smoke_failed: bool) -> list:
    """Returns the gates that apply, lowest cap first."""
    by_id = {r.id: r for r in results}
    conditions = {
        "smoke_failed": smoke_failed,
        "security_critical": bool(_security_findings(results, "critical")),
        "security_high": bool(_security_findings(results, "high")),
        "critical_flow_failed": bool(by_id.get("flows") and by_id["flows"].details.get("critical_flow_failed")),
        "load_error_rate": bool(by_id.get("load") and by_id["load"].details.get("error_rate_pct", 0) > 5),
    }
    applied = [g for g in cfg["gates"] if conditions.get(g["id"])]
    return sorted(applied, key=lambda g: g["cap"])


# --------------------------------------------------------------- scorecard ---
def compute(results: list, cfg: dict, profile: str, smoke_failed: bool = False) -> dict:
    weights = cfg["profiles"][profile]
    by_id = {r.id: r for r in results}
    categories = []

    for cat_id, cat_cfg in cfg["categories"].items():
        checks = []
        for check_id, check_cfg in cat_cfg["checks"].items():
            result = by_id.get(check_id)
            tested = bool(result and result.tested and result.score is not None)
            checks.append({
                "id": check_id, "name": check_cfg["name"], "share": check_cfg["share"], "tested": tested,
                "score": round(result.score, 1) if tested else None,
                "summary": result.summary if result else "",
                "method": result.method if result else "",
                "reason": "" if tested else ((result.reason if result else "") or check_cfg.get("needs", "Not run")),
            })
        tested_share = sum(c["share"] for c in checks if c["tested"])
        for c in checks:
            c["effective_share"] = c["share"] / tested_share if c["tested"] else 0.0
        score = sum(c["score"] * c["effective_share"] for c in checks if c["tested"]) if tested_share else None
        categories.append({
            "id": cat_id, "name": cat_cfg["name"], "weight": weights[cat_id],
            "tested": tested_share > 0, "tested_share": tested_share,
            "score": round(score, 1) if score is not None else None, "checks": checks,
        })

    tested_weight = sum(c["weight"] for c in categories if c["tested"])
    for c in categories:
        c["effective_weight"] = c["weight"] / tested_weight if c["tested"] else 0.0
    raw = sum(c["score"] * c["effective_weight"] for c in categories if c["tested"]) if tested_weight else 0.0

    gates = evaluate_gates(results, cfg, smoke_failed)
    overall = min([raw] + [g["cap"] for g in gates])
    overall_rounded = int(round(overall))
    level = level_for(overall_rounded, cfg["levels"])

    return {
        "score": overall_rounded,
        "raw_score": int(round(raw)),
        "capped": bool(gates) and gates[0]["cap"] < raw,
        "gates": [{"id": g["id"], "cap": g["cap"], "label": g["label"]} for g in gates],
        "level": level["level"], "level_name": level["name"], "level_meaning": level["meaning"],
        "profile": profile,
        # Weight points of the categories that were tested at all (the spec's "x of 100 tested").
        "weight_tested": tested_weight,
        # The same figure counted check by check: how deep the tested part goes.
        "depth_tested": round(sum(c["weight"] * c["tested_share"] / 100 for c in categories), 1),
        "categories": categories,
    }


# ------------------------------------------------------ impact per finding ---
def assign_impact(results: list, scorecard: dict, cfg: dict) -> list:
    """Works out how many overall points each finding costs, flags gate triggers,
    numbers the findings and returns them most severe first."""
    effective = {}
    for cat in scorecard["categories"]:
        for check in cat["checks"]:
            effective[check["id"]] = cat["effective_weight"] * check["effective_share"]
    gate_caps = {g["id"]: g["cap"] for g in scorecard["gates"]}

    findings = []
    for result in results:
        if not result.tested:
            continue
        if result.method == "findings" and result.findings:
            # Share the points the check actually lost in proportion to each finding's deduction.
            total = sum(cfg["deductions"].get(f.severity, 0) for f in result.findings)
            lost = 100.0 - (result.score or 0.0)
            for f in result.findings:
                f.loss = lost * cfg["deductions"].get(f.severity, 0) / total if total else 0.0
        for f in result.findings:
            f.impact_points = round((f.loss or 0.0) * effective.get(result.id, 0.0), 2)
            if result.category == "security" and f.severity in ("critical", "high"):
                cap = gate_caps.get(f"security_{f.severity}")
                if cap is not None:
                    f.gate = f"Caps the score at {cap}"
            findings.append(f)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.impact_points, f.title))
    for index, f in enumerate(findings, start=1):
        f.id = f"QA-{index:03d}"
    return findings


def fix_order(findings: list) -> list:
    """Fix list: gate triggers first (they cap the score), then by points returned."""
    actionable = [f for f in findings if f.gate or f.impact_points > 0]
    return sorted(actionable, key=lambda f: (0 if f.gate else 1, SEVERITY_ORDER.get(f.severity, 9)
                                             if f.gate else 0, -f.impact_points))


def not_tested(check_id: str, category: str, reason: str = "") -> CheckResult:
    return CheckResult(id=check_id, category=category, tested=False, reason=reason)
