"""URL helpers."""
from __future__ import annotations

import ipaddress
from urllib.parse import urldefrag, urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}

# Extensions the crawler does not parse as pages (they are still link-checked).
NON_PAGE_EXTENSIONS = (
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".exe", ".dmg", ".apk", ".iso",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
    ".mp3", ".mp4", ".webm", ".avi", ".mov", ".wav", ".ogg",
    ".css", ".js", ".mjs", ".json", ".xml", ".rss", ".atom", ".txt", ".csv",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".woff", ".woff2", ".ttf", ".eot",
)


def normalize(url: str) -> str:
    """Canonical form used to recognise the same URL twice: no fragment, no default port."""
    url, _ = urldefrag(url.strip())
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host if port in (None, DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def origin_of(url: str) -> str:
    parts = urlsplit(normalize(url))
    return f"{parts.scheme}://{parts.netloc}"


def same_origin(a: str, b: str) -> bool:
    return origin_of(a) == origin_of(b)


def same_host(a: str, b: str) -> bool:
    return (urlsplit(a).hostname or "").lower() == (urlsplit(b).hostname or "").lower()


def is_http_url(url: str) -> bool:
    return urlsplit(url).scheme.lower() in ("http", "https")


def looks_like_page(url: str) -> bool:
    return not urlsplit(url).path.lower().endswith(NON_PAGE_EXTENSIONS)


def is_local_host(host: str) -> bool:
    host = (host or "").lower().strip("[]")
    if host in ("localhost",) or host.endswith((".localhost", ".local", ".test", ".internal")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def short(text: str, limit: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
