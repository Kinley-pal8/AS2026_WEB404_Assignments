#!/usr/bin/env python3
"""
WEB404 Assignment 3 - SSRF + Access Control - VULNERABLE build.

A "URL preview" feature: paste a link, the SERVER fetches it and returns a
snippet - the same pattern chat apps and social platforms use to render link
previews. Nothing here restricts what gets fetched:

  1. No scheme check - file://, and in other libraries even gopher:// or
     dict://, are fetched just like http(s)://.
  2. No destination check - any hostname or IP the string names is fetched,
     including loopback, link-local, and private ranges.
  3. Redirects are followed automatically (urlopen()'s default behaviour),
     so even a URL that looks external can hop into an internal address.
  4. No authorization - anyone can call /preview with no login at all,
     turning the server into an anonymous, unaccountable network proxy.

Run on localhost only.

    python3 vulnerable/app.py     # serves http://127.0.0.1:7001

Endpoints
    GET  /            landing page
    POST /preview     url=<...> -> fetched status/content-type/snippet
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "7001"))
SNIPPET_LEN = 500


def fetch_preview(url: str) -> dict:
    # No scheme check, no destination check - urlopen() also follows HTTP
    # redirects transparently by default.
    with urllib.request.urlopen(url, timeout=5) as resp:
        body = resp.read(SNIPPET_LEN)
        return {
            "requested_url": url,
            "final_url": resp.geturl(),
            "status": resp.status,
            "content_type": resp.headers.get("Content-Type"),
            "snippet": body.decode("utf-8", "replace"),
        }


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>LinkPeek (vulnerable)</title>
<h1>LinkPeek - vulnerable build</h1>
<p>Paste any URL and the server will fetch and preview it. No login required.</p>
<form id="f">
  <input name="url" size="60" placeholder="https://example.com">
  <button>Preview</button>
</form>
<pre id="out"></pre>
<script>
document.getElementById('f').onsubmit = async (e) => {{
  e.preventDefault();
  const fd = new URLSearchParams(new FormData(e.target));
  const r = await fetch('/preview', {{method: 'POST', body: fd}});
  document.getElementById('out').textContent = await r.text();
}};
</script>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "LinkPeek/1.0"

    def _json(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urllib.parse.urlparse(self.path).path == "/":
            self._html(200, PAGE.encode())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/preview":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        url = form.get("url", [""])[0]
        if not url:
            self._json(400, {"error": "url is required"})
            return
        try:
            self._json(200, fetch_preview(url))
        except (urllib.error.URLError, ValueError, ConnectionError) as exc:
            self._json(502, {"error": f"fetch failed: {exc}"})

    def log_message(self, *_):
        pass


def main():
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[vulnerable] http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
