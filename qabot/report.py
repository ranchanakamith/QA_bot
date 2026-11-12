"""Writes the JSON and HTML reports."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES = Path(__file__).with_name("templates")


def _ns(value):
    """Dicts become attribute-accessible so the template can write r.score.level."""
    if isinstance(value, dict):
        return _Dot({k: _ns(v) for k, v in value.items()})
    if isinstance(value, list):
        return [_ns(v) for v in value]
    return value


class _Dot(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


def render_html(report: dict) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "j2"]),
                      trim_blocks=True, lstrip_blocks=True)
    r = _ns(report)
    by_id = {f["id"]: f for f in r.findings}
    severities = Counter(f["severity"] for f in r.findings)
    counts = SimpleNamespace(
        critical=severities["critical"], high=severities["high"], medium=severities["medium"],
        low=severities["low"], info=severities["info"],
        categories_tested=sum(1 for c in r.score.categories if c.tested))
    return env.get_template("report.html.j2").render(
        r=r, counts=counts,
        fixes=[by_id[i] for i in r.fix_list if i in by_id],
        names={c.id: c.name for c in r.score.categories},
        speed=r.check_details.get("page_speed"))


def write_reports(report: dict, out_dir: str | Path, pdf: bool = False, cfg: dict | None = None) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {"json": out / "report.json", "html": out / "report.html"}
    slim = {k: v for k, v in report.items() if k != "screenshots"}     # keep the JSON small and diff-friendly
    paths["json"].write_text(json.dumps(slim, indent=2, ensure_ascii=False), encoding="utf-8")
    paths["html"].write_text(render_html(report), encoding="utf-8")
    if pdf and cfg is not None:
        from .browser import BrowserSession
        session, reason = BrowserSession.try_start(cfg)
        if session is None:
            paths["pdf_error"] = reason
        else:
            try:
                paths["pdf"] = out / "report.pdf"
                session.save_pdf(str(paths["html"]), str(paths["pdf"]))
            finally:
                session.close()
    return paths
