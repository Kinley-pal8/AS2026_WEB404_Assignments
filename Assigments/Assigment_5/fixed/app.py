#!/usr/bin/env python3
"""
WEB404 Assignment 5 - Server-Side Template Injection (SSTI) - FIXED build.

Same CardForge feature, same endpoints, same output for honest input - but
the structural mistake is gone. Three independent controls, each of which
alone defeats the vulnerable build's three techniques:

  1. SEPARATE CODE FROM DATA (the real fix). User input is bound as a
     VARIABLE to a fixed, developer-authored template. The template source is
     a constant the user never influences, so nothing the user types is ever
     compiled as template code. {{ 7*7 }} comes back as the five literal
     characters "{{ 7*7 }}", not 49.

  2. AUTO-ESCAPING. The environment escapes HTML in rendered values, so the
     same input is also inert in the browser (no stored XSS as a bonus).

  3. SANDBOXED ENVIRONMENT (defence in depth). Even if a future change
     reintroduced from_string() on user input, SandboxedEnvironment blocks the
     attribute walks (__init__, __globals__, ...) that every RCE gadget needs,
     raising SecurityError instead of running code.

    python3 fixed/app.py          # serves http://127.0.0.1:9002

Endpoints
    GET  /            landing page
    POST /preview     body=<...> -> rendered card HTML (or an error)
"""
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from jinja2 import select_autoescape
from jinja2.sandbox import SandboxedEnvironment

PORT = int(os.environ.get("PORT", "9002"))

CONFIG = {
    "SECRET_KEY": "s3cr3t-signing-key-do-not-leak",
    "DB_PASSWORD": "hunter2-prod",
    "DEBUG": True,
}
USER = {"name": "Guest", "tier": "free"}

# Sandboxed + auto-escaping environment (controls 2 and 3).
env = SandboxedEnvironment(autoescape=select_autoescape(default=True))

# Control 1: the template is a CONSTANT authored by us. The only user-
# controllable thing is the VALUE bound to `body`, which is data, never code.
CARD_TEMPLATE = env.from_string(
    "<div class='card'>{{ body }}</div>"
)
# The {{ user.name }} convenience from the vulnerable build is offered safely
# by giving the user ONE explicit, pre-approved placeholder instead of the
# whole template language: we substitute it ourselves, as plain text.
NAME_TOKEN = "{{ user.name }}"


def render_card(body: str) -> str:
    # Honour the single supported placeholder by string replacement, BEFORE
    # the value becomes template data. This never invokes the engine on user
    # text, so it cannot be used to inject new placeholders.
    body = body.replace(NAME_TOKEN, USER["name"])
    # Bind as data. `config`/`user` are NOT passed here, so even a bypass of
    # control 1 would have nothing sensitive in scope to leak.
    return CARD_TEMPLATE.render(body=body)


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>CardForge (fixed)</title>
<h1>CardForge - fixed build</h1>
<p>Type a greeting. Use <code>{{ user.name }}</code> to insert the name.</p>
<form id="f">
  <textarea name="body" rows="3" cols="60">Hi {{ user.name }}, welcome!</textarea><br>
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
    server_version = "CardForge/1.0"

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
        body = form.get("body", [""])[0]
        if not body:
            self._json(400, {"error": "body is required"})
            return
        try:
            self._json(200, {"rendered": render_card(body)})
        except Exception as exc:  # noqa: BLE001 - demo surfaces engine errors
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def log_message(self, *_):
        pass


def main():
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[fixed] http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
