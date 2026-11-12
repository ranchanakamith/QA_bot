"""A small practice website for the QA bot.

    python demo_site/server.py            # the site with planted defects, on http://127.0.0.1:8765
    python demo_site/server.py --good     # the same site with the defects fixed

Every defect in the default mode is deliberate, so you can see what the bot
finds. Do not copy this code into a real project.
"""
from __future__ import annotations

import argparse
import struct
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def png(width: int, height: int, rgb: tuple) -> bytes:
    """A solid-colour PNG, built by hand so the demo needs no image file."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    row = b"\x00" + bytes(rgb) * width
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(row * height)) + chunk(b"IEND", b""))


PIXEL = png(120, 120, (43, 76, 126))

NAV = '<nav><a href="/">Home</a> <a href="/about">About</a> <a href="/contact">Contact</a> <a href="/products">Products</a></nav>'
STYLE = """
body { font-family: system-ui, sans-serif; margin: 0; padding: 24px; color: #1b1f24; line-height: 1.5; }
nav a { margin-right: 14px; } main { max-width: 720px; }
img { max-width: 100%; } input, button { font: inherit; padding: 6px 10px; }
.hero { width: 120px; height: 120px; }
"""


def page(title: str, body: str, good: bool, head: str = "") -> str:
    lang = ' lang="en"' if good else ""
    viewport = '<meta name="viewport" content="width=device-width, initial-scale=1">' if good else ""
    return (f"<!DOCTYPE html><html{lang}><head><meta charset=\"utf-8\">{viewport}<title>{title}</title>"
            f"<style>{STYLE}</style>{head}</head><body>{NAV}<main>{body}</main></body></html>")


def pages(good: bool) -> dict:
    if good:
        return {
            "/": page("Demo shop", '<h1>Demo shop</h1><p>Everything on this version works.</p>'
                      '<img class="hero" src="/static/logo.png" alt="Demo shop logo" width="120" height="120">'
                      '<h2>Start here</h2><p><a href="/products">See the products</a></p>', good),
            "/about": page("About", "<h1>About</h1><p>We sell demo products.</p>", good),
            "/contact": page("Contact", '<h1>Contact</h1><form method="post" action="/contact">'
                             '<label for="email">Email</label> <input id="email" name="email" type="email"> '
                             '<button type="submit">Send</button></form>', good),
            "/products": page("Products", "<h1>Products</h1><ul><li>Widget</li><li>Gadget</li></ul>", good),
        }
    return {
        "/": page("Demo shop", '<h1>Demo shop</h1>'
                  '<p style="color:#b8b8b8">Pale grey text that is hard to read.</p>'
                  '<img class="hero" src="/static/logo.png">'                       # no alt text
                  '<h4>Start here</h4>'                                              # skips h2 and h3
                  '<p><a href="/products">See the products</a> · <a href="/old-page">Old page</a> · '   # /old-page is a 404
                  '<a href="/report">Sales report</a> · <a href="/wide">Size chart</a></p>'             # /report is a 500
                  '<img src="/static/missing.png" alt="Banner">'                    # missing image
                  '<div onclick="location.href=\'/about\'">Read more</div>', good),  # not keyboard accessible
        "/about": page("", "<h1>About</h1><p>We sell demo products.</p>"             # empty title
                       "<script>undefinedFunction();</script>", good),              # JavaScript error
        "/contact": page("Contact", '<h1>Contact</h1><form method="get" action="/contact">'
                         '<input name="email" type="text" placeholder="Email"> '    # no label
                         '<input name="password" type="password" placeholder="Password"> '
                         '<button type="submit"></button></form>'                   # button without a name
                         '<a href="/about" style="outline:none">About us</a>', good,
                         head="<style>a:focus, input:focus, button:focus { outline: none; }</style>"),
        "/products": page("Products", "<h1>Products</h1><ul><li>Widget</li><li>Gadget</li></ul>"
                          '<script>fetch("/api/stock")</script>', good),            # the API call fails with 500
        "/wide": page("Size chart", '<h1>Size chart</h1><table style="width:1400px"><tr><td>S</td><td>M</td><td>L</td></tr></table>', good),
    }


TRACEBACK = """<html><body><h1>Internal Server Error</h1><pre>Traceback (most recent call last):
  File "/srv/app/views.py", line 42, in sales_report
    total = sum(row.amount for row in rows) / len(rows)
ZeroDivisionError: division by zero</pre></body></html>"""


class Handler(BaseHTTPRequestHandler):
    good = False
    server_version = "DemoServer/1.0"

    def log_message(self, *args):   # keep the console quiet
        pass

    def send(self, status: int, body, content_type: str = "text/html; charset=utf-8", extra: dict | None = None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if self.good:
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        else:
            self.send_header("X-Powered-By", "DemoFramework/2.3.1")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def version_string(self):
        return "DemoServer" if self.good else "DemoServer/1.0"

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self.send(200, page("Thanks", "<h1>Thanks</h1><p>Message received.</p>", self.good))

    def do_GET(self):
        path = self.path.split("?")[0]
        site = pages(self.good)
        if path == "/static/logo.png":
            return self.send(200, PIXEL, "image/png")
        if path == "/robots.txt":
            return self.send(200, "User-agent: *\nAllow: /\n", "text/plain")
        if path == "/contact":
            cookie = "sessionid=abc123; Path=/; HttpOnly; SameSite=Lax" if self.good else "sessionid=abc123; Path=/"
            return self.send(200, site[path], extra={"Set-Cookie": cookie})
        if path in site:
            return self.send(200, site[path])
        if not self.good:
            if path == "/report":
                time.sleep(0.3)
                return self.send(500, TRACEBACK)
            if path == "/api/stock":
                return self.send(500, '{"error": "database unavailable"}', "application/json")
            if path == "/.env":
                return self.send(200, "DB_PASSWORD=demo-only-not-a-real-secret\nAPI_KEY=demo\n", "text/plain")
            if path == "/.git/HEAD":
                return self.send(200, "ref: refs/heads/main\n", "text/plain")
        self.send(404, page("Not found", "<h1>Page not found</h1><p>That page does not exist.</p>", self.good))


def make_server(port: int = 8765, good: bool = False) -> ThreadingHTTPServer:
    handler = type("DemoHandler", (Handler,), {"good": good})
    return ThreadingHTTPServer(("127.0.0.1", port), handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--good", action="store_true", help="serve the version without defects")
    options = parser.parse_args()
    server = make_server(options.port, options.good)
    print(f"Demo site ({'clean' if options.good else 'with planted defects'}) on http://127.0.0.1:{options.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
