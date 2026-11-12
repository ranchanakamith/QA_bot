"""A polite HTTP client: one session, a fixed user agent, a rate limit on the target."""
from __future__ import annotations

import threading
import time

import requests


class HttpClient:
    def __init__(self, crawl_cfg: dict):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = crawl_cfg["user_agent"]
        self.session.headers["Accept"] = "text/html,application/xhtml+xml,*/*;q=0.8"
        self.timeout = crawl_cfg["timeout_seconds"]
        self.verify = True
        self._interval = 1.0 / max(float(crawl_cfg["requests_per_second"]), 0.1)
        self._lock = threading.Lock()
        self._last = 0.0

    def _wait(self) -> None:
        with self._lock:
            delay = self._last + self._interval - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._last = time.monotonic()

    def request(self, method: str, url: str, throttle: bool = True, **kwargs) -> requests.Response:
        """throttle=True for requests to the target site; False for third-party hosts."""
        if throttle:
            self._wait()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("allow_redirects", True)
        return self.session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def close(self) -> None:
        self.session.close()


def describe_error(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS error"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timed out"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "redirect loop"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection failed"
    return type(exc).__name__


def set_cookie_headers(response: requests.Response) -> list:
    """Raw Set-Cookie values from a response and the redirects that led to it."""
    values = []
    for resp in list(response.history) + [response]:
        raw = getattr(resp, "raw", None)
        headers = getattr(raw, "headers", None)
        if headers is not None and hasattr(headers, "getlist"):
            values.extend(headers.getlist("Set-Cookie"))
        elif "Set-Cookie" in resp.headers:
            values.append(resp.headers["Set-Cookie"])
    return values
