#!/usr/bin/env python3
"""
WEB404 Assignment 5 - Server-Side Template Injection (SSTI) - VULNERABLE build.

"CardForge": a greeting-card preview feature. The user types the body of a
card and the server renders it with Jinja2 so that placeholders like
{{ user.name }} get filled in. The mistake is structural, not a missing
filter:

    the user's raw input is CONCATENATED INTO THE TEMPLATE SOURCE and then
    compiled and executed by the template engine.

That means the engine treats whatever the user typed as *template code*, not
as *data*. Jinja2 expressions therefore run on the server with the full power
of the Python process:

  1. {{ 7*7 }}   proves the input is evaluated (returns 49, not "7*7").
  2. {{ config }} leaks any object the app put in the render scope - here a
     config dict holding a signing key and a DB password.
  3. {{ cycler.__init__.__globals__.os.popen('id').read() }} walks from a
     harmless built-in global to the os module and runs a shell command:
     remote code execution.

Run on localhost only. This process will execute attacker-supplied commands.

    python3 vulnerable/app.py     # serves http://127.0.0.1:9001

Endpoints
    GET  /            landing page
    POST /preview     body=<...> -> rendered card HTML (or an error)
"""
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from jinja2 import Environment

PORT = int(os.environ.get("PORT", "9001"))

# Objects the app exposes to its templates. In a real app these come from the
# framework (Flask puts `config` in the Jinja scope automatically); exposing
# them is normal and safe *as long as user input is never template code*.
CONFIG = {
    "SECRET_KEY": "s3cr3t-signing-key-do-not-leak",
    "DB_PASSWORD": "hunter2-prod",
    "DEBUG": True,
}
USER = {"name": "Guest", "tier": "free"}

env = Environment()


def render_card(body: str) -> str:
    # THE BUG: user input is spliced into the template SOURCE, so the engine
    # compiles and runs it as template code. The {{ user.name }} default is
    # only there to make the "it's just a template" framing believable.
    source = "<div class='card'>" + body + "</div>"
    template = env.from_string(source)
    return template.render(config=CONFIG, user=USER)


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>CardForge (vulnerable)</title>
<h1>CardForge - vulnerable build</h1>
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
    print(f"[vulnerable] http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
