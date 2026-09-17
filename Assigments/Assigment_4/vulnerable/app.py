#!/usr/bin/env python3
"""
WEB404 Assignment 4 - Cross-Site Scripting (XSS) - VULNERABLE build.

"QuickNotes": a tiny public noticeboard with three unrelated XSS sinks, one
per XSS type:

  1. Reflected  - GET /search?q=... echoes the query straight into the page.
  2. Stored     - POST /notes saves a note; GET / renders every stored note
                  straight into the page, for every visitor, from then on.
  3. DOM-based  - client-side JS on / reads location.hash (a URL fragment,
                  which never reaches the server at all) and writes it into
                  the page with innerHTML.

Every response also sets a plain session cookie with no HttpOnly/SameSite,
so a successful payload can read it via document.cookie - the real-world
impact of these bugs is usually session theft, not a harmless alert box.

Run on localhost only.

    python3 vulnerable/app.py     # serves http://127.0.0.1:8001

Endpoints
    GET  /             landing page: search box, note form, stored notes,
                        DOM XSS sink
    GET  /search?q=    reflected XSS sink
    POST /notes        author=&message= -> stored XSS sink
    GET  /collect?c=   records data "exfiltrated" by a PoC payload; stands
                        in for an attacker-controlled server for this demo
                        (see exploits/03-cookie-theft.sh)
    GET  /collected    JSON dump of what /collect has received so far
"""
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8001"))

NOTES = []       # [{"author": ..., "message": ...}, ...] - stored XSS sink
COLLECTED = []    # data received by the fake attacker endpoint /collect

PAGE = """<!doctype html>
<meta charset="utf-8">
<title>QuickNotes (vulnerable)</title>
<h1>QuickNotes - vulnerable build</h1>

<h2>Search notes</h2>
<form method="get" action="/search">
  <input name="q" placeholder="search...">
  <button>Search</button>
</form>
{search_result}

<h2>Post a note</h2>
<form method="post" action="/notes">
  <input name="author" placeholder="your name">
  <input name="message" placeholder="your note" size="40">
  <button>Post</button>
</form>

<h2>Notes</h2>
<div id="notes">
{notes_html}
</div>

<h2 id="welcome"></h2>
<script>
  // DOM-based XSS sink: untrusted data (the URL fragment) goes straight
  // into innerHTML with no encoding. location.hash is never sent to the
  // server, so this executes purely in the browser.
  var name = decodeURIComponent(location.hash.slice(1)) || 'guest';
  document.getElementById('welcome').innerHTML = 'Welcome, ' + name + '!';
</script>
"""


def render_notes():
    if not NOTES:
        return "<p><i>No notes yet.</i></p>"
    # VULNERABLE: author/message inserted with no output encoding at all.
    return "".join(
        f"<div class='note'><b>{n['author']}</b>: {n['message']}</div>"
        for n in NOTES
    )


def render_page(search_result=""):
    return PAGE.format(search_result=search_result, notes_html=render_notes()).encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "QuickNotes/1.0"

    def _headers(self, code, length, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        # VULNERABLE: no HttpOnly, no SameSite - readable via document.cookie
        # and sent on cross-site requests.
        self.send_header("Set-Cookie", "session_id=demo-session-abc123")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _send(self, code, body: bytes, ctype="text/html; charset=utf-8"):
        self._headers(code, len(body), ctype)
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/":
            self._send(200, render_page())
        elif parsed.path == "/search":
            q = params.get("q", [""])[0]
            # VULNERABLE: the search term is echoed back with no encoding.
            result = f"<p>Showing results for: {q}</p>" if q else ""
            self._send(200, render_page(search_result=result))
        elif parsed.path == "/collect":
            COLLECTED.append(params.get("c", [""])[0])
            self._send(200, b"ok")
        elif parsed.path == "/collected":
            self._send(200, json.dumps(COLLECTED, indent=2).encode(), ctype="application/json")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        if self.path != "/notes":
            self._send(404, b"not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        author = form.get("author", ["anon"])[0] or "anon"
        message = form.get("message", [""])[0]
        # VULNERABLE: stored verbatim, rendered verbatim to every visitor later.
        NOTES.append({"author": author, "message": message})
        self._headers(303, 0, extra={"Location": "/"})

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
