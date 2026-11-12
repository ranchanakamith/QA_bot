"""Browser-based measurements through Playwright. Everything here is optional:
when no browser can be started the scan still runs, and the browser-only checks
are reported as not tested."""
from __future__ import annotations

import base64
import os
import shutil

from .models import Page

CHROME_PATHS = (
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
)
QUIET_ARGS = ["--disable-background-networking", "--disable-component-update", "--no-first-run"]

# Runs before any page script: records the paint, layout-shift and long-task entries
# that the performance check turns into FCP, LCP, CLS and TBT.
PERF_OBSERVER_JS = """
(() => {
  const q = window.__qabot = {lcp: 0, cls: 0, fcp: 0, longTasks: []};
  const watch = (type, fn) => {
    try { new PerformanceObserver(list => list.getEntries().forEach(fn)).observe({type, buffered: true}); } catch (e) {}
  };
  watch('largest-contentful-paint', e => { q.lcp = e.startTime; });
  watch('paint', e => { if (e.name === 'first-contentful-paint') q.fcp = e.startTime; });
  watch('longtask', e => { q.longTasks.push([e.startTime, e.duration]); });
  let windowValue = 0, windowStart = 0, windowLast = 0;
  watch('layout-shift', e => {
    if (e.hadRecentInput) return;
    if (windowValue && e.startTime - windowLast < 1000 && e.startTime - windowStart < 5000) {
      windowValue += e.value;
    } else {
      windowValue = e.value; windowStart = e.startTime;
    }
    windowLast = e.startTime;
    if (windowValue > q.cls) q.cls = windowValue;
  });
})();
"""

PERF_READ_JS = """
() => {
  const q = window.__qabot || {lcp: 0, cls: 0, fcp: 0, longTasks: []};
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const res = performance.getEntriesByType('resource');
  const tbt = q.longTasks.filter(t => t[0] >= q.fcp).reduce((sum, t) => sum + Math.max(0, t[1] - 50), 0);
  return {
    fcp_ms: q.fcp, lcp_ms: q.lcp || q.fcp, cls: q.cls, tbt_ms: tbt,
    ttfb_ms: nav.responseStart || 0, load_ms: nav.loadEventEnd || 0,
    requests: res.length + 1,
    transfer_bytes: res.reduce((sum, r) => sum + (r.transferSize || 0), nav.transferSize || 0),
  };
}
"""

# Marks elements a sighted user cannot see, so the accessibility rules can skip them.
MARK_HIDDEN_JS = """
() => {
  const sel = 'img,a,button,input,select,textarea,iframe,h1,h2,h3,h4,h5,h6';
  for (const el of document.querySelectorAll(sel)) {
    const style = getComputedStyle(el);
    if (!el.getClientRects().length || style.visibility === 'hidden' || el.closest('[aria-hidden="true"]')) {
      el.setAttribute('data-qabot-hidden', '1');
    }
  }
}
"""

OVERFLOW_JS = """
() => ({
  scrollWidth: document.documentElement.scrollWidth,
  innerWidth: document.documentElement.clientWidth,
  viewportMeta: (document.querySelector('meta[name=viewport]') || {}).content || '',
})
"""

# WCAG 1.4.3 contrast: text colour against the nearest opaque background colour.
CONTRAST_JS = """
([normalMin, largeMin]) => {
  const parse = c => {
    const m = /rgba?\\(([^)]+)\\)/.exec(c || '');
    if (!m) return null;
    const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(parseFloat);
    return p.length < 3 || p.some(isNaN) ? null : {r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1};
  };
  const blend = (top, under) => ({
    r: top.r * top.a + under.r * (1 - top.a), g: top.g * top.a + under.g * (1 - top.a),
    b: top.b * top.a + under.b * (1 - top.a), a: 1});
  const lum = c => {
    const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  };
  const background = el => {
    const layers = [];
    for (let node = el; node && node.nodeType === 1; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.backgroundImage !== 'none' || parseFloat(style.opacity) < 1) return null;
      const bg = parse(style.backgroundColor);
      if (!bg) return null;
      if (bg.a > 0) layers.push(bg);
      if (bg.a === 1) break;
    }
    let colour = {r: 255, g: 255, b: 255, a: 1};
    for (const layer of layers.reverse()) colour = blend(layer, colour);
    return colour;
  };
  const hex = c => '#' + [c.r, c.g, c.b].map(v => Math.round(v).toString(16).padStart(2, '0')).join('');
  let checked = 0;
  const failures = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const seen = new Set();
  while (walker.nextNode() && checked < 600) {
    const text = walker.currentNode.nodeValue.trim();
    const el = walker.currentNode.parentElement;
    if (!text || !el || seen.has(el) || el.closest('script,style,noscript,[aria-hidden="true"]')) continue;
    seen.add(el);
    const style = getComputedStyle(el);
    if (!el.getClientRects().length || style.visibility === 'hidden') continue;
    const fg0 = parse(style.color), bg = background(el);
    if (!fg0 || !bg) continue;
    const fg = blend(fg0, bg);
    const l1 = lum(fg), l2 = lum(bg);
    const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    const size = parseFloat(style.fontSize), bold = parseInt(style.fontWeight, 10) >= 700;
    const large = size >= 24 || (bold && size >= 18.66);
    checked++;
    if (ratio < (large ? largeMin : normalMin) - 0.01) {
      failures.push({text: text.slice(0, 60), ratio: Math.round(ratio * 100) / 100,
                     fg: hex(fg), bg: hex(bg), required: large ? largeMin : normalMin});
    }
  }
  return {checked, failures: failures.slice(0, 25), failed: failures.length};
}
"""

KEYBOARD_SETUP_JS = """
() => {
  const sel = 'a[href], button, input:not([type=hidden]), select, textarea, summary, [tabindex]';
  const radios = new Set();
  const els = [...document.querySelectorAll(sel)].filter(el => {
    if (el.disabled || el.tabIndex < 0 || !el.getClientRects().length) return false;
    if (getComputedStyle(el).visibility === 'hidden') return false;
    if (el.type === 'radio' && el.name) {          // Tab stops once per radio group
      if (radios.has(el.name)) return false;
      radios.add(el.name);
    }
    return true;
  });
  const sig = el => {
    const s = getComputedStyle(el);
    return [s.outlineStyle, s.outlineWidth, s.outlineColor, s.boxShadow, s.borderColor,
            s.backgroundColor, s.color, s.textDecorationLine].join('|');
  };
  els.forEach((el, i) => { el.setAttribute('data-qabot-k', i); el.setAttribute('data-qabot-sig', sig(el)); });
  const clickOnly = [...document.querySelectorAll('[onclick]')].filter(el =>
    !el.matches('a[href],button,input,select,textarea,summary') && !(el.hasAttribute('tabindex') && el.tabIndex >= 0));
  return {
    count: els.length,
    positiveTabindex: [...document.querySelectorAll('[tabindex]')].filter(el => el.tabIndex > 0).length,
    clickOnly: clickOnly.length,
    clickOnlySample: clickOnly.length ? clickOnly[0].outerHTML.slice(0, 120) : '',
  };
}
"""

KEYBOARD_STEP_JS = """
() => {
  const el = document.activeElement;
  if (!el || el === document.body || !el.hasAttribute('data-qabot-k')) return null;
  const s = getComputedStyle(el);
  const sig = [s.outlineStyle, s.outlineWidth, s.outlineColor, s.boxShadow, s.borderColor,
               s.backgroundColor, s.color, s.textDecorationLine].join('|');
  const outlined = s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0;
  return {k: +el.getAttribute('data-qabot-k'), visible: outlined || sig !== el.getAttribute('data-qabot-sig'),
          html: el.outerHTML.slice(0, 120)};
}
"""


class BrowserSession:
    """One Chromium instance used for every browser-based check in a scan."""

    def __init__(self, playwright, browser, cfg: dict, ignore_https_errors: bool):
        self._pw = playwright
        self.browser = browser
        self.cfg = cfg
        self.ignore_https_errors = ignore_https_errors
        self.timeout = cfg["browser"]["page_timeout_seconds"] * 1000
        self.version = browser.version
        self.user_agent = cfg["crawl"]["user_agent"]

    # ------------------------------------------------------------ lifecycle
    @classmethod
    def try_start(cls, cfg: dict, ignore_https_errors: bool = False):
        """Returns (session, reason). session is None when no browser could be started."""
        if str(cfg["browser"]["enabled"]).lower() == "false":
            return None, "browser checks were switched off"
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return None, "Playwright is not installed (pip install playwright, then: playwright install chromium)"
        pw = sync_playwright().start()
        args = list(QUIET_ARGS)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.append("--no-sandbox")
        attempts = []
        if cfg["browser"]["executable"]:
            attempts.append({"executable_path": cfg["browser"]["executable"]})
        attempts.append({})                       # Playwright's own Chromium
        attempts.append({"channel": "chrome"})    # an installed Google Chrome
        candidates = [chrome_on_path()] + [p for p in CHROME_PATHS if os.path.exists(p)]
        attempts += [{"executable_path": p} for p in dict.fromkeys(c for c in candidates if c)]
        last_error = ""
        for options in attempts:
            try:
                browser = pw.chromium.launch(args=args, **options)
                return cls(pw, browser, cfg, ignore_https_errors), ""
            except Exception as exc:
                last_error = str(exc).splitlines()[0]
        pw.stop()
        return None, f"no Chromium or Chrome could be started ({last_error}); run: playwright install chromium"

    def close(self) -> None:
        try:
            self.browser.close()
        finally:
            self._pw.stop()

    def _context(self, viewport: str = "desktop", browser=None):
        size = self.cfg["browser"]["viewports"][viewport]
        return (browser or self.browser).new_context(
            viewport={"width": size["width"], "height": size["height"]},
            ignore_https_errors=self.ignore_https_errors,
            is_mobile=(viewport == "phone" and browser is None),
            has_touch=(viewport == "phone" and browser is None),
        )

    def _goto(self, page, url: str) -> None:
        page.goto(url, wait_until="load", timeout=self.timeout)
        try:
            page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            pass  # long-polling pages never go idle; the load event is enough

    @staticmethod
    def _listen(page, record: dict) -> None:
        def on_console(msg):
            if msg.type == "error" and not msg.text.startswith("Failed to load resource"):
                record["console_errors"].append(msg.text[:300])

        def on_response(resp):
            request = resp.request
            if resp.status >= 400 and not (request.is_navigation_request() and request.frame.parent_frame is None):
                if not resp.url.endswith("/favicon.ico"):
                    record["failed_requests"].append({"url": resp.url, "status": resp.status,
                                                      "error": "", "type": request.resource_type})

        def on_failed(request):
            error = request.failure or ""
            if "ERR_ABORTED" not in error:
                record["failed_requests"].append({"url": request.url, "status": None,
                                                  "error": error, "type": request.resource_type})

        page.on("console", on_console)
        page.on("pageerror", lambda exc: record["page_errors"].append(str(exc)[:300]))
        page.on("response", on_response)
        page.on("requestfailed", on_failed)

    # ------------------------------------------------------- per-page visit
    def visit(self, page_record: Page) -> None:
        """Desktop load of one crawled page: JS errors, failed requests, rendered DOM, contrast."""
        record = {"console_errors": [], "page_errors": [], "failed_requests": [], "loaded": False}
        page_record.browser = record
        context = self._context("desktop")
        page = context.new_page()
        self._listen(page, record)
        try:
            self._goto(page, page_record.final_url)
            record["loaded"] = True
            a11y = self.cfg["accessibility"]
            record["contrast"] = page.evaluate(CONTRAST_JS, [a11y["contrast_normal"], a11y["contrast_large"]])
            record["overflow"] = page.evaluate(OVERFLOW_JS)
            page.evaluate(MARK_HIDDEN_JS)
            record["rendered_html"] = page.content()
        except Exception as exc:
            record["load_error"] = str(exc).splitlines()[0][:200]
        finally:
            context.close()

    # ---------------------------------------------------------- performance
    def measure(self, url: str) -> dict:
        """Lab performance metrics for one page, on a phone viewport, optionally throttled."""
        perf = self.cfg["performance"]
        context = self._context("phone")
        page = context.new_page()
        page.add_init_script(PERF_OBSERVER_JS)
        try:
            if perf["throttle"] == "mobile":
                t = perf["mobile_throttle"]
                cdp = context.new_cdp_session(page)
                cdp.send("Network.enable")
                cdp.send("Network.emulateNetworkConditions", {
                    "offline": False, "latency": t["latency_ms"],
                    "downloadThroughput": t["download_kbps"] * 1024 / 8,
                    "uploadThroughput": t["upload_kbps"] * 1024 / 8})
                cdp.send("Emulation.setCPUThrottlingRate", {"rate": t["cpu_slowdown"]})
            self._goto(page, url)
            page.wait_for_timeout(1000)   # let late layout shifts and long tasks land
            metrics = page.evaluate(PERF_READ_JS)
            metrics["url"] = url
            return metrics
        except Exception as exc:
            return {"url": url, "error": str(exc).splitlines()[0][:200]}
        finally:
            context.close()

    # ------------------------------------------------------------ viewports
    def viewport_check(self, url: str, viewport: str, screenshot: bool = False) -> dict:
        context = self._context(viewport)
        page = context.new_page()
        try:
            self._goto(page, url)
            result = page.evaluate(OVERFLOW_JS)
            if screenshot:
                image = page.screenshot(type="jpeg", quality=55)
                result["screenshot"] = base64.b64encode(image).decode("ascii")
            return result
        except Exception as exc:
            return {"error": str(exc).splitlines()[0][:200]}
        finally:
            context.close()

    # ------------------------------------------------------------- keyboard
    def keyboard_check(self, url: str) -> dict:
        """Tabs through the page like a keyboard-only user."""
        context = self._context("desktop")
        page = context.new_page()
        try:
            self._goto(page, url)
            setup = page.evaluate(KEYBOARD_SETUP_JS)
            expected = min(setup["count"], 50)
            reached, without_indicator, sample = set(), 0, ""
            for _ in range(expected + 2 if expected else 0):
                page.keyboard.press("Tab")
                step = page.evaluate(KEYBOARD_STEP_JS)
                if step is None or step["k"] in reached:
                    continue
                reached.add(step["k"])
                if not step["visible"]:
                    without_indicator += 1
                    sample = sample or step["html"]
            setup.update({"expected": expected, "reached": len(reached),
                          "without_indicator": without_indicator, "indicator_sample": sample})
            return setup
        except Exception as exc:
            return {"error": str(exc).splitlines()[0][:200]}
        finally:
            context.close()

    # -------------------------------------------------------- other engines
    def other_engines(self) -> tuple:
        """Launches the extra engines that are installed. Returns ({name: browser}, [missing names])."""
        engines, missing = {}, []
        for name in self.cfg["browser"]["extra_engines"]:
            try:
                engines[name] = getattr(self._pw, name).launch()
            except Exception:
                missing.append(name)
        return engines, missing

    def engine_check(self, browser, url: str) -> dict:
        record = {"console_errors": [], "page_errors": [], "failed_requests": []}
        context = self._context("desktop", browser=browser)
        page = context.new_page()
        self._listen(page, record)
        try:
            self._goto(page, url)
            record["text_length"] = page.evaluate("document.body ? document.body.innerText.length : 0")
        except Exception as exc:
            record["load_error"] = str(exc).splitlines()[0][:200]
        finally:
            context.close()
        return record

    # ------------------------------------------------------------------ pdf
    def save_pdf(self, html_path: str, pdf_path: str) -> None:
        context = self.browser.new_context()
        page = context.new_page()
        try:
            from pathlib import Path
            page.goto(Path(html_path).resolve().as_uri(), wait_until="load")
            page.emulate_media(media="print")
            page.pdf(path=pdf_path, format="A4", print_background=True,
                     margin={"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"})
        finally:
            context.close()


def chrome_on_path() -> str | None:
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    return None
