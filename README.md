# QA Bot

Scans a website the way a QA engineer would start: smoke test, crawl, checks, then a
defect report with one 0–100 quality score and a level from 1 to 5.

This is **Phase 1** of the design spec: the black-box, URL-only audit.

## Quick start (Windows)

```powershell
cd D:\QA_bot
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium

python -m qabot scan https://your-site.example --out reports\first-run
```

Open `reports\first-run\report.html` in a browser. `report.json` holds the same data for scripts and CI.

Without the `playwright install` step the bot still runs, and the browser-only checks
(JavaScript errors, contrast, keyboard, screen sizes, paint metrics) are reported as not tested.

## Try it on the practice site

The repository includes a small website with planted defects, and a fixed version of it.

```powershell
python demo_site\server.py                 # terminal 1: defects, http://127.0.0.1:8765
python -m qabot scan 127.0.0.1:8765 --i-own-this-site --out reports\demo-bad

python demo_site\server.py --good --port 8766
python -m qabot scan 127.0.0.1:8766 --i-own-this-site --out reports\demo-good --baseline reports\demo-bad\report.json
```

The first scan scores 39 (capped by an exposed `.env` file); the second scores 100.

## Options

| Option | What it does |
| --- | --- |
| `--profile general\|transactional\|content` | Which weight set to use (default `general`) |
| `--out FOLDER` | Where `report.html` and `report.json` go |
| `--max-pages N` | Crawl limit (default 30) |
| `--i-own-this-site` | Confirms ownership and enables the exposed-file probes (`/.env`, `/.git/HEAD`, …) |
| `--baseline report.json` | Compare with an earlier run: score change, fixed and new issues |
| `--fail-under SCORE` | Exit code 1 below this score, for CI pipelines |
| `--pdf` | Also write `report.pdf` |
| `--no-browser` | HTTP-only scan |
| `--no-external` | Do not verify links to other sites |
| `--ignore-robots` | Crawl pages `robots.txt` disallows |
| `--config my.yaml` | Override weights, thresholds, gates or limits |

## What Phase 1 tests

| Category | Weight | Checks that run now |
| --- | --- | --- |
| Functional correctness | 25 | Broken links, missing resources, JavaScript errors, failed requests |
| Security | 20 | Passive scan (mixed content, password forms, missing SRI, directory listing, CORS), exposed-file probes, cookie attributes, TLS, security headers |
| Performance and load | 15 | Page speed in the lab: LCP, CLS, TBT, FCP on a throttled phone profile |
| Reliability and backend health | 15 | Server error rate in normal use, 404 behaviour, crash on odd input, stack-trace leaks |
| Accessibility and usability | 10 | 12 WCAG rules including contrast, plus a keyboard walk-through |
| Browser and device compatibility | 5 | Phone, tablet and desktop layout; Firefox and WebKit when installed |
| Code quality | 10 | Not yet: needs the source repository (Phase 4) |

Checks that cannot run are left out of the score, their weight is shared among the rest,
and the report lists each one with the reason.

## How the score works

1. Every check scores 0–100 by one of three rules:
   - pass/fail tests: passed ÷ total × 100
   - measured values: 100 at the "good" threshold, 0 at "poor", a straight line between
   - findings: start at 100; subtract 40 per critical, 20 per high, 8 per medium, 2 per low. The same issue on many pages counts once.
2. A category score is the weighted average of its tested checks.
3. The overall score is the weighted average of the tested categories.
4. Gates cap the result: smoke test fails → 0; critical security finding → 39; high security finding → 74.
5. Levels: 90–100 is 5, 75–89 is 4, 60–74 is 3, 40–59 is 2, 0–39 is 1.

All of these numbers live in `qabot/default.yaml`. They are tunable defaults, not an industry standard.

## Project layout

```
qabot/
  default.yaml        weights, thresholds, gates, limits
  cli.py              command line
  scan.py             the pipeline: smoke test, discovery, checks, score
  crawler.py          smoke test, crawl, link verification
  browser.py          Playwright measurements
  scoring.py          the scoring model
  report.py           HTML, JSON and PDF output
  checks/             one module per category
  templates/          the HTML report
demo_site/server.py   practice site with planted defects
tests/                scoring tests and end-to-end tests
```

Run the tests with `pip install pytest` then `python -m pytest tests`.

## Rules for using it

- Scan only sites you own or have written permission to test.
- Phase 1 sends ordinary page requests at 5 per second and no attack payloads.
- A score means "no defects found by these checks", not "no defects".

## Known limits of this version

- Accessibility and page speed use the bot's own rules and measurements. axe-core and Lighthouse are not integrated yet, so numbers will differ from those tools.
- Page speed is a single lab run per page; real-user values differ.
- Pages behind a login are not reached. Forms are listed but not submitted.
- Ownership is taken on the user's word (`--i-own-this-site`). Verification by DNS record or file comes with the load tests in Phase 3.

## Roadmap

2. Functional depth: test logins, generated form tests, end-to-end flows.
3. Backend and load: API contract tests, ownership verification, load, stress, spike and soak tests.
4. Security and white-box: active scan, access-control checks, code scans, coverage.
5. Product features: run history, CI integration, fix suggestions.
