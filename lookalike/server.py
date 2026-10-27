import json
import os
import subprocess
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from .analyze import check
from .qr import QRError, decode_png

WEB = Path(__file__).parent / "web"
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
MAX_JSON = 64 * 1024
MAX_PNG = 4 * 1024 * 1024
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def make_server(brands, port=0):
    class Handler(BaseHTTPRequestHandler):
        server_version = "lookalike/" + __version__

        def log_message(self, *args):
            pass

        def _allowed_hosts(self):
            p = self.server.server_address[1]
            return {"127.0.0.1:%d" % p, "localhost:%d" % p}

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj).encode(), "application/json")

        def _host_ok(self):
            if self.headers.get("Host", "") not in self._allowed_hosts():
                self._json(403, {"error": "bad Host header"})
                return False
            return True

        def do_GET(self):
            if not self._host_ok():
                return
            entry = STATIC.get(self.path.split("?", 1)[0])
            if entry is None:
                self._json(404, {"error": "not found"})
                return
            self._send(200, (WEB / entry[0]).read_bytes(), entry[1])

        def do_POST(self):
            if not self._host_ok():
                return
            origin = self.headers.get("Origin")
            if origin is None or origin not in {"http://" + h for h in self._allowed_hosts()}:
                self._json(403, {"error": "bad Origin"})
                return
            limit = MAX_PNG if self.path == "/api/qr" else MAX_JSON
            try:
                n = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._json(411, {"error": "Content-Length required"})
                return
            if n < 0 or n > limit:
                self._json(413, {"error": "body too large"})
                return
            body = self.rfile.read(n)
            try:
                if self.path == "/api/check":
                    req = json.loads(body)
                    if not isinstance(req, dict) or not isinstance(req.get("input"), str):
                        raise ValueError("expected {\"input\": string}")
                    reports = check(req["input"], brands, html=bool(req.get("html")))
                    self._json(200, {"reports": reports})
                elif self.path == "/api/qr":
                    text = decode_png(body)
                    self._json(200, {"text": text, "reports": check(text, brands)})
                else:
                    self._json(404, {"error": "not found"})
            except (ValueError, QRError) as e:
                self._json(400, {"error": str(e)})

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def open_browser(url, browser=None):
    browser = browser or os.environ.get("BROWSER")
    if browser:
        subprocess.Popen([browser, url])
    else:
        webbrowser.open(url)


def serve(brands, port=0, no_open=False, browser=None):
    httpd = make_server(brands, port)
    url = "http://127.0.0.1:%d/" % httpd.server_address[1]
    print("lookalike gui at " + url + "  (Ctrl+C to stop)", flush=True)
    if not no_open:
        open_browser(url, browser)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
