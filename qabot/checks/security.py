"""Security, Phase 1: passive checks only. Nothing here sends attack payloads.

The few direct probes (/.env, /.git/HEAD ...) run only when the user confirms
ownership with --i-own-this-site.
"""
from __future__ import annotations

import datetime as dt
import re
import socket
import ssl
import warnings
from urllib.parse import urlsplit

import requests

from ..crawler import soup_of
from ..models import CheckResult, FindingSet, ScanContext
from ..scoring import findings_score
from ..util import same_origin, short

CATEGORY = "security"
VERSION_IN_HEADER = re.compile(r"\d+\.\d+")
WEAK_CSP = re.compile(r"(script-src|default-src)[^;]*('unsafe-inline'|'unsafe-eval'|\s\*(\s|;|$))")


def run(ctx: ScanContext) -> list:
    return [dynamic_scan(ctx), auth_session(ctx), tls_headers(ctx)]


def _is_https(ctx: ScanContext) -> bool:
    return ctx.origin.startswith("https://")


def _skip_transport(ctx: ScanContext) -> bool:
    return ctx.is_local and ctx.config["security"]["local_targets_skip_transport"]


# ---------------------------------------------------------- passive scan ---
def dynamic_scan(ctx: ScanContext) -> CheckResult:
    findings = FindingSet(CATEGORY, "dynamic_scan")
    https = _is_https(ctx)

    for page in ctx.html_pages:
        soup = soup_of(page.dom)
        location = page.final_url

        if https:
            for kind, url in page.resources:
                if url.startswith("http://"):
                    active = kind in ("script", "stylesheet", "frame")
                    findings.add(
                        "mixed-content-active" if active else "mixed-content-passive",
                        f"{'Scripts or styles' if active else 'Images or media'} loaded over plain HTTP on an HTTPS page",
                        "medium" if active else "low", location,
                        description="An HTTPS page pulls in a resource over HTTP, where it can be read or altered in transit.",
                        expected="Every resource is loaded over HTTPS", actual=f"{kind} loaded from {short(url, 100)}",
                        evidence=url, fix="Load the resource over https:// or host it on the site.",
                        reference="OWASP A04:2025 Cryptographic Failures")

        for form in page.forms:
            if not form["has_password"]:
                continue
            if not _skip_transport(ctx) and (not https or form["action"].startswith("http://")):
                findings.add(
                    "password-over-http", "Password form is sent over plain HTTP", "high", location,
                    description="A form with a password field is served or submitted without encryption, "
                                "so credentials can be read on the network.",
                    expected="Login pages and their form targets use HTTPS", actual=f"Form posts to {form['action']}",
                    evidence=form["action"], fix="Serve the page and the form target over HTTPS only.",
                    reference="OWASP A04:2025 Cryptographic Failures")
            if form["method"] == "get":
                findings.add(
                    "password-in-url", "Password form uses GET, which puts the password in the URL", "medium", location,
                    description="GET forms place field values in the URL, where they end up in history, logs and referrers.",
                    expected="Forms with password fields use POST", actual="method=\"get\"",
                    evidence=form["action"], fix="Change the form method to POST.",
                    reference="OWASP A07:2025 Authentication Failures")

        for tag in soup.select("script[src], link[rel~=stylesheet][href]"):
            src = tag.get("src") or tag.get("href") or ""
            if src.startswith(("http://", "https://", "//")):
                absolute = "https:" + src if src.startswith("//") else src
                if not same_origin(absolute, ctx.origin) and not tag.get("integrity"):
                    findings.add(
                        "missing-sri", "Third-party scripts or styles are loaded without Subresource Integrity", "low",
                        location,
                        description="If the third-party host is compromised, the changed file runs on this site unchecked.",
                        expected="Third-party <script> and <link> tags carry an integrity attribute",
                        actual=short(str(tag), 160), evidence=short(str(tag), 200),
                        fix="Add integrity and crossorigin attributes, or host the file on the site.",
                        reference="OWASP A08:2025 Software or Data Integrity Failures")

        title = soup.title.get_text(strip=True) if soup.title else ""
        if title.lower().startswith(("index of /", "directory listing for")):
            findings.add(
                "directory-listing", "Directory listing is enabled", "medium", location,
                description="The server lists the files in a folder, which exposes files that were never linked.",
                expected="Folders without an index page return 403 or 404", actual=f"Page title: {title}",
                evidence=title, fix="Turn off directory listing in the web server configuration.",
                reference="OWASP A02:2025 Security Misconfiguration")

        acao = page.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" and page.headers.get("Access-Control-Allow-Credentials", "").lower() == "true":
            findings.add(
                "cors-wildcard-credentials", "CORS allows any origin together with credentials", "medium", location,
                description="This combination signals a CORS policy that trusts every website.",
                expected="Credentialed CORS responses name specific trusted origins",
                actual="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                fix="Return a specific allowed origin, or drop Access-Control-Allow-Credentials.",
                reference="OWASP A02:2025 Security Misconfiguration")

    probes_run = 0
    if ctx.owned:
        for probe in ctx.config["security"]["probes"]:
            url = ctx.origin + probe["path"]
            try:
                resp = ctx.http.get(url, allow_redirects=False)
            except requests.RequestException:
                continue
            probes_run += 1
            if resp.status_code == 200 and re.search(probe["signature"], resp.text[:5000], re.M):
                findings.add(
                    probe["rule"], probe["title"], probe["severity"], url,
                    description="A file that should never be public is served by the site. "
                                "Such files often hold passwords, keys or the full source history.",
                    expected=f"{probe['path']} returns 403 or 404", actual="HTTP 200 with matching content",
                    evidence=f"GET {probe['path']} returned HTTP 200 (content withheld from this report)",
                    fix="Block the path in the web server, remove the file from the web root, and rotate any secret it held.",
                    reference="OWASP A02:2025 Security Misconfiguration")

    found = findings.list()
    scope = "Passive checks only (no attack requests)"
    scope += f", plus {probes_run} exposed-file probes" if probes_run else "; exposed-file probes need --i-own-this-site"
    return CheckResult(
        "dynamic_scan", CATEGORY, score=findings_score(found, ctx.config["deductions"]), method="findings",
        summary=f"{len(found)} issue{'s' if len(found) != 1 else ''} found. {scope}. The active scan arrives in Phase 4.",
        findings=found, details={"probes_run": probes_run, "mode": "passive"})


# ---------------------------------------------------------------- cookies ---
def parse_set_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True) for p in parts[1:]}
    return {"name": name, "attrs": attrs}


def auth_session(ctx: ScanContext) -> CheckResult:
    cookies = {}
    for page in ctx.pages:
        for raw in page.set_cookies:
            cookie = parse_set_cookie(raw)
            cookies.setdefault(cookie["name"], (cookie, page.final_url))
    if not cookies:
        return CheckResult("auth_session", CATEGORY, tested=False)

    findings = FindingSet(CATEGORY, "auth_session")
    session_like = re.compile(ctx.config["security"]["session_cookie_pattern"], re.I)
    check_secure = _is_https(ctx) and not _skip_transport(ctx)
    for name, (cookie, location) in cookies.items():
        attrs = cookie["attrs"]
        is_session = bool(session_like.search(name))
        severity = "medium" if is_session else "low"
        kind = "Session cookie" if is_session else "Cookie"
        rule_suffix = "session" if is_session else "other"
        if "httponly" not in attrs:
            findings.add(
                f"cookie-no-httponly-{rule_suffix}", f"{kind} is readable by JavaScript (no HttpOnly)", severity, location,
                description="Without HttpOnly, a script injected into the page can read the cookie and take over the session.",
                expected="Session cookies carry the HttpOnly attribute", actual=f"Set-Cookie: {name}=… without HttpOnly",
                evidence=name, fix="Add HttpOnly to the cookie.", reference="OWASP A07:2025 Authentication Failures")
        if check_secure and "secure" not in attrs:
            findings.add(
                f"cookie-no-secure-{rule_suffix}", f"{kind} can be sent over plain HTTP (no Secure)", severity, location,
                description="Without Secure, the browser also sends the cookie on unencrypted requests.",
                expected="Cookies on an HTTPS site carry the Secure attribute", actual=f"Set-Cookie: {name}=… without Secure",
                evidence=name, fix="Add Secure to the cookie.", reference="OWASP A04:2025 Cryptographic Failures")
        if "samesite" not in attrs:
            findings.add(
                "cookie-no-samesite", "Cookie has no SameSite attribute", "low", location,
                description="SameSite limits when the cookie is sent on requests from other sites, which blunts CSRF.",
                expected="Cookies set SameSite=Lax or Strict", actual=f"Set-Cookie: {name}=… without SameSite",
                evidence=name, fix="Add SameSite=Lax (or Strict) to the cookie.",
                reference="OWASP A01:2025 Broken Access Control")

    found = findings.list()
    return CheckResult(
        "auth_session", CATEGORY, score=findings_score(found, ctx.config["deductions"]), method="findings",
        summary=f"Cookie attributes checked on {len(cookies)} cookie{'s' if len(cookies) != 1 else ''}; "
                "login, session and access-control tests need two test accounts (Phase 4).",
        findings=found, details={"cookies": sorted(cookies)})


# -------------------------------------------------------- TLS and headers ---
def tls_probe(host: str, port: int, timeout: float = 8.0) -> dict:
    """Negotiated protocol, certificate expiry, and whether TLS 1.0/1.1 is still accepted."""
    info: dict = {}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                info["protocol"] = tls.version()
                der = tls.getpeercert(binary_form=True)
        try:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(der)
            expires = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
            info["expires"] = expires.date().isoformat()
            info["days_left"] = (expires - dt.datetime.now(dt.timezone.utc)).days
        except ImportError:
            pass   # expiry needs the 'cryptography' package; certificate validity is still checked by requests
    except (OSError, ssl.SSLError) as exc:
        info["error"] = type(exc).__name__
        return info

    try:
        legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy.check_hostname = False
        legacy.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():            # offering deprecated versions is the point of this probe
            warnings.simplefilter("ignore", DeprecationWarning)
            legacy.minimum_version = ssl.TLSVersion.TLSv1
            legacy.maximum_version = ssl.TLSVersion.TLSv1_1
        legacy.set_ciphers("DEFAULT:@SECLEVEL=0")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with legacy.wrap_socket(sock, server_hostname=host) as tls:
                info["legacy_protocol"] = tls.version()
    except Exception:
        info["legacy_protocol"] = None    # refused, or this machine's OpenSSL cannot offer TLS 1.0/1.1
    return info


def tls_headers(ctx: ScanContext) -> CheckResult:
    findings = FindingSet(CATEGORY, "tls_headers")
    https = _is_https(ctx)
    details: dict = {"https": https}
    notes = []

    # ---- transport
    if _skip_transport(ctx):
        notes.append("HTTPS and TLS were not assessed because the target is a local address")
    elif not https:
        findings.add(
            "no-https", "The site is served over plain HTTP", "high", ctx.origin,
            description="Without HTTPS, everything users send and receive, including passwords, can be read or changed in transit.",
            expected="The site is served over HTTPS and HTTP redirects to it", actual=f"{ctx.origin} answers over HTTP",
            fix="Install a TLS certificate (for example from Let's Encrypt) and redirect HTTP to HTTPS.",
            reference="OWASP A04:2025 Cryptographic Failures")
    else:
        parts = urlsplit(ctx.origin)
        if ctx.tls_error:
            findings.add(
                "tls-cert-invalid", "The TLS certificate is not trusted", "high", ctx.origin,
                description="Browsers show a full-page warning for this certificate (expired, self-signed or wrong host name).",
                expected="A valid certificate issued for this host name", actual=short(ctx.tls_error, 200),
                fix="Install a valid certificate for this host name and its full chain.",
                reference="OWASP A04:2025 Cryptographic Failures")
        info = tls_probe(parts.hostname, parts.port or 443)
        details["tls"] = info
        if info.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.add(
                "tls-old-protocol", f"The server negotiates the outdated {info['protocol']}", "high", ctx.origin,
                expected="TLS 1.2 or 1.3", actual=info["protocol"], fix="Enable TLS 1.2 and 1.3 and disable older versions.",
                description="This protocol version has known weaknesses and modern browsers refuse it.",
                reference="OWASP A04:2025 Cryptographic Failures")
        elif info.get("legacy_protocol"):
            findings.add(
                "tls-legacy-accepted", f"The server still accepts {info['legacy_protocol']}", "medium", ctx.origin,
                description="TLS 1.0 and 1.1 are deprecated; accepting them allows downgrade to weaker encryption.",
                expected="Only TLS 1.2 and 1.3 are accepted", actual=f"Handshake with {info['legacy_protocol']} succeeded",
                fix="Disable TLS 1.0 and 1.1 in the server or load-balancer configuration.",
                reference="OWASP A04:2025 Cryptographic Failures")
        days = info.get("days_left")
        if days is not None and not ctx.tls_error and days < 14:
            findings.add(
                "tls-cert-expiring", f"The TLS certificate expires in {days} days", "medium", ctx.origin,
                description="When the certificate expires, browsers block the site.",
                expected="More than 14 days of validity left", actual=f"Expires {info.get('expires')}",
                fix="Renew the certificate and automate renewal.", reference="OWASP A04:2025 Cryptographic Failures")
        try:
            if parts.port not in (None, 443):
                raise requests.RequestException("non-standard port: no HTTP twin to test")
            resp = ctx.http.get("http://" + parts.hostname + "/", allow_redirects=True, timeout=8)
            if not resp.url.startswith("https://"):
                findings.add(
                    "no-https-redirect", "HTTP requests are not redirected to HTTPS", "medium", "http://" + parts.hostname,
                    description="Visitors who type the address without https:// stay on an unencrypted connection.",
                    expected="http:// redirects to https://", actual=f"http:// answered with HTTP {resp.status_code} and no redirect to HTTPS",
                    fix="Redirect every HTTP request to HTTPS with a 301.", reference="OWASP A04:2025 Cryptographic Failures")
        except requests.RequestException:
            pass   # port 80 closed: nothing is served over HTTP, which is fine

    # ---- response headers
    for page in ctx.html_pages:
        headers, location = page.headers, page.final_url
        csp = headers.get("Content-Security-Policy", "")

        if https and not _skip_transport(ctx) and "Strict-Transport-Security" not in headers:
            findings.add(
                "missing-hsts", "No Strict-Transport-Security header", "low", location,
                description="Without HSTS, a first visit over HTTP can be intercepted before the redirect to HTTPS.",
                expected="Strict-Transport-Security: max-age=31536000; includeSubDomains", actual="Header absent",
                fix="Send the Strict-Transport-Security header on every HTTPS response.",
                reference="OWASP A02:2025 Security Misconfiguration")
        if not csp:
            findings.add(
                "missing-csp", "No Content-Security-Policy header", "medium", location,
                description="A Content Security Policy limits which scripts may run and is the main defence in depth against cross-site scripting.",
                expected="A Content-Security-Policy header that restricts script sources", actual="Header absent",
                fix="Add a Content-Security-Policy; start with default-src 'self' and loosen it only where needed.",
                reference="OWASP A02:2025 Security Misconfiguration")
        elif WEAK_CSP.search(csp):
            findings.add(
                "weak-csp", "The Content-Security-Policy allows unsafe script sources", "low", location,
                description="'unsafe-inline', 'unsafe-eval' or a wildcard source removes most of the protection a CSP gives.",
                expected="script-src without 'unsafe-inline', 'unsafe-eval' or *", actual=short(csp, 200),
                evidence=short(csp, 300), fix="Use nonces or hashes for inline scripts and list script hosts explicitly.",
                reference="OWASP A02:2025 Security Misconfiguration")
        if "X-Frame-Options" not in headers and "frame-ancestors" not in csp:
            findings.add(
                "missing-clickjacking-protection", "The page can be framed by other sites (clickjacking)", "medium", location,
                description="Another site can load this page in an invisible frame and trick users into clicking on it.",
                expected="X-Frame-Options: DENY or SAMEORIGIN, or a CSP frame-ancestors directive", actual="Neither is set",
                fix="Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: SAMEORIGIN).",
                reference="OWASP A02:2025 Security Misconfiguration")
        if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
            findings.add(
                "missing-nosniff", "No X-Content-Type-Options: nosniff header", "low", location,
                description="Without it, browsers may guess a file's type and run an uploaded file as script.",
                expected="X-Content-Type-Options: nosniff", actual="Header absent or different",
                fix="Send X-Content-Type-Options: nosniff on every response.",
                reference="OWASP A02:2025 Security Misconfiguration")
        if "Referrer-Policy" not in headers:
            findings.add(
                "missing-referrer-policy", "No Referrer-Policy header", "info", location,
                description="A referrer policy controls how much of the page URL is sent to other sites.",
                expected="Referrer-Policy: strict-origin-when-cross-origin", actual="Header absent",
                fix="Send a Referrer-Policy header.", reference="OWASP A02:2025 Security Misconfiguration")
        for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
            value = headers.get(name, "")
            if value and (name != "Server" or VERSION_IN_HEADER.search(value)):
                findings.add(
                    f"version-disclosure-{name.lower()}", f"The {name} header reveals the server software and version", "low", location,
                    description="Exact product versions tell an attacker which known vulnerabilities to try.",
                    expected="No product versions in response headers", actual=f"{name}: {value}",
                    evidence=f"{name}: {value}", fix="Remove the header or strip the version in the server configuration.",
                    reference="OWASP A02:2025 Security Misconfiguration")

    found = findings.list()
    summary = f"{len(found)} issue{'s' if len(found) != 1 else ''} across {len(ctx.html_pages)} pages"
    if notes:
        summary += ". " + "; ".join(notes)
    return CheckResult("tls_headers", CATEGORY, score=findings_score(found, ctx.config["deductions"]),
                       method="findings", summary=summary, findings=found, details=details)
