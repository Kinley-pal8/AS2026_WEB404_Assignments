#!/usr/bin/env python3
"""
WEB404 Assignment 4 - Cross-Site Scripting (XSS) - FIXED build.

Same "QuickNotes" feature set as the vulnerable build. Five independent
defences, each closing one gap:

  1. Context-aware output encoding - html.escape() is applied to every piece
     of user data at the moment it is written into HTML (the search term,
     and each note's author/message). This is the PRIMARY defence for
     reflected and stored XSS: the browser sees "&lt;script&gt;", literal
     text, never a tag.
  2. Input sanitisation - length caps and control-character stripping on
     stored input. This is DEFENCE IN DEPTH, not the fix: a blocklist of
     "dangerous" substrings is well known to be bypassable (case, encoding,
     nesting), so it is deliberately not used here. The property that
     actually stops execution is #1.
  3. DOM-based fix - the client-side sink now uses `textContent` instead of
     `innerHTML`. textContent never parses its argument as markup, so there
     is no sink left to inject into, regardless of what location.hash
     contains.
  4. Content-Security-Policy - sent on every response, with no
     'unsafe-inline' in script-src. Even if an encoding bug slipped through
     somewhere, an injected <script> or onerror="..." handler still would
     not execute, because the browser refuses to run inline script per the
     policy. This is defence in depth for the whole page, not a fix for any
     one sink.
  5. Secure cookie attributes - HttpOnly (JavaScript cannot read the cookie
     via document.cookie at all, closing off the most common XSS payoff even
     if a payload did execute) and SameSite=Lax (cookie is not sent on most
     cross-site requests). `Secure` is intentionally NOT set here because
     this demo serves plain HTTP on localhost - browsers drop `Secure`
     cookies entirely over HTTP, which would break the demo. Any real
     deployment (which is HTTPS) must add `Secure` as well.

    python3 fixed/app.py     # serves http://127.0.0.1:8002

Endpoints: identical to the vulnerable build (see vulnerable/app.py).
"""
import html
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8002"))

MAX_AUTHOR_LEN = 40
MAX_MESSAGE_LEN = 300

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)

NOTES = []       # [{"author": ..., "message": ...}, ...]
COLLECTED = []    # data received by the fake attacker endpoint /collect

PAGE = """<!doctype html>
<meta charset="utf-8">
<title>QuickNotes (fixed)</title>
<h1>QuickNotes - fixed build</h1>

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
  // FIXED: textContent never parses its argument as HTML, so there is no
  // markup sink here at all, regardless of what location.hash contains.
  var name = decodeURIComponent(location.hash.slice(1)) || 'guest';
  document.getElementById('welcome').textContent = 'Welcome, ' + name + '!';
</script>
"""


def sanitize(value: str, max_len: int) -> str:
    # Defence in depth ONLY - strips control characters and caps length.
    # This is not what stops script execution; html.escape() at render time
    # (below) is.
    cleaned = "".join(ch for ch in value if ch == " " or ch.isprintable())
    return cleaned[:max_len]


def render_notes():
    if not NOTES:
        return "<p><i>No notes yet.</i></p>"
    # FIXED: every field is HTML-escaped at the point of output.
    return "".join(
        f"<div class='note'><b>{html.escape(n['author'])}</b>: {html.escape(n['message'])}</div>"
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
        self.send_header("Content-Security-Policy", CSP)
        # FIXED: HttpOnly blocks document.cookie; SameSite=Lax blocks most
        # cross-site sends. No Secure flag - see module docstring #5.
        self.send_header("Set-Cookie", "session_id=demo-session-abc123; HttpOnly; SameSite=Lax")
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
            # FIXED: escaped at output time, same as the stored notes.
            result = f"<p>Showing results for: {html.escape(q)}</p>" if q else ""
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
        author = sanitize(form.get("author", ["anon"])[0] or "anon", MAX_AUTHOR_LEN)
        message = sanitize(form.get("message", [""])[0], MAX_MESSAGE_LEN)
        NOTES.append({"author": author, "message": message})
        self._headers(303, 0, extra={"Location": "/"})

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
