#!/usr/bin/env python3
"""Local demonstration server (NOT a real website).

Serves a few paths on 127.0.0.1 with deliberately chosen headers so you can
reproduce sample-output/ yourself without scanning anyone else's site.

    python tests/demo_server.py            # listens on http://127.0.0.1:8080
    python scanner.py http://127.0.0.1:8080/

Paths:
    /          mixed results (PASS, WARN and FAIL)
    /hardened  all headers set (HTTP, so HSTS is SKIP)
    /bare      no security headers at all
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROUTES = {
    "/": [
        ("Content-Security-Policy",
         "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'self'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "unsafe-url"),
    ],
    "/hardened": [
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "geolocation=(), camera=()"),
    ],
    "/bare": [],
}


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        headers = ROUTES.get(self.path)
        if headers is None:
            self.send_response(404)
            headers = []
        else:
            self.send_response(200)
        for name, value in headers:
            self.send_header(name, value)
        body = b"demo\n"
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # keep the console quiet
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler)
    print(f"Demo server on http://127.0.0.1:{args.port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
