"""Command line:  python -m qabot scan https://example.com"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_config
from .report import write_reports
from .scan import compare, run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qabot", description="Automated website QA audit with a weighted 0-100 score.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a website and write a report")
    scan.add_argument("url", help="Start URL, e.g. https://example.com or localhost:8000")
    scan.add_argument("--profile", default="general", help="Weight profile: general, transactional or content")
    scan.add_argument("--out", default="qabot-report", help="Folder for report.html and report.json")
    scan.add_argument("--config", help="YAML file that overrides parts of the default configuration")
    scan.add_argument("--max-pages", type=int, help="Maximum number of pages to crawl (default 30)")
    scan.add_argument("--no-browser", action="store_true", help="Skip the browser-based checks")
    scan.add_argument("--no-external", action="store_true", help="Do not verify links to other sites")
    scan.add_argument("--ignore-robots", action="store_true", help="Crawl pages that robots.txt disallows")
    scan.add_argument("--i-own-this-site", action="store_true", dest="owned",
                      help="Confirm you own the site; enables the exposed-file probes")
    scan.add_argument("--baseline", help="Earlier report.json to compare this run with")
    scan.add_argument("--fail-under", type=int, metavar="SCORE", help="Exit with code 1 when the score is below SCORE (for CI)")
    scan.add_argument("--pdf", action="store_true", help="Also write report.pdf")
    scan.add_argument("--quiet", action="store_true", help="Print only the final result")
    return parser


def main(argv: list | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):      # Windows consoles may not be UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    overrides: dict = {"crawl": {}, "browser": {}}
    if args.max_pages:
        overrides["crawl"]["max_pages"] = args.max_pages
    if args.no_external:
        overrides["crawl"]["check_external"] = False
    if args.ignore_robots:
        overrides["crawl"]["respect_robots"] = False
    if args.no_browser:
        overrides["browser"]["enabled"] = False
    try:
        cfg = load_config(args.config, overrides)
    except (OSError, ValueError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    if args.profile not in cfg["profiles"]:
        print(f"Unknown profile '{args.profile}'. Choose from: {', '.join(cfg['profiles'])}", file=sys.stderr)
        return 2

    log = (lambda *_: None) if args.quiet else print
    report = run_scan(args.url, cfg, profile=args.profile, owned=args.owned, log=log)
    if args.baseline:
        try:
            compare(report, json.loads(Path(args.baseline).read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError) as exc:
            print(f"Could not read the baseline report: {exc}", file=sys.stderr)
    paths = write_reports(report, args.out, pdf=args.pdf, cfg=cfg)

    score = report["score"]
    print()
    print(f"Score: {score['score']}/100  Level {score['level']} ({score['level_name']})")
    if score["capped"]:
        print(f"  capped from {score['raw_score']}: {score['gates'][0]['label']}")
    if not report["smoke"]["passed"]:
        print(f"  smoke test failed: {report['smoke']['reason']}")
    for cat in score["categories"]:
        shown = f"{cat['score']:.0f}" if cat["tested"] else "not tested"
        print(f"  {cat['name']:<34} weight {cat['weight']:>2}   {shown}")
    print(f"Findings: {len(report['findings'])}   Weight tested: {score['weight_tested']}/100")
    print(f"Report: {paths['html']}")
    if "pdf" in paths:
        print(f"PDF:    {paths['pdf']}")
    elif "pdf_error" in paths:
        print(f"PDF not written: {paths['pdf_error']}", file=sys.stderr)

    if args.fail_under is not None and score["score"] < args.fail_under:
        print(f"Score {score['score']} is below --fail-under {args.fail_under}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
