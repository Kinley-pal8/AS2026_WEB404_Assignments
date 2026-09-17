#!/usr/bin/env python3
"""
WEB404 Assignment 1 - SQL Injection - FIXED build.

Same three features as the vulnerable build, same HTML, same database - the only
differences are in how the database is queried. Defences applied:

  1. Parameterised queries (bound "?" placeholders) everywhere - user input is
     never concatenated into SQL text, so it can never change the query shape.
  2. Input validation - /product only accepts a positive integer id; /search
     caps the term length. (Defence in depth; not the primary control.)
  3. Least-privilege database handle - the web role connects read-only
     (mode=ro), so even a hypothetical injection could not write or drop.
  4. Safe error handling - database errors are logged server-side and the client
     only ever sees a generic message, so there is no error-based oracle.
  5. Generic authentication response - "Login failed." for both bad username and
     bad password, so login cannot be used as a boolean oracle either.

    python3 db/seed.py       # once, to (re)create db/app.db
    python3 fixed/app.py     # serves http://127.0.0.1:5002
"""
import html
import os
import re
import sqlite3
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "db", "app.db"))
PORT = int(os.environ.get("PORT", "5002"))

MAX_SEARCH_LEN = 100
ID_RE = re.compile(r"^[0-9]{1,9}$")


def db():
    # Least privilege: open the database read-only. A write/DDL attempt raises
    # "attempt to write a readonly database" instead of succeeding.
    return sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>SafeShop (fixed)</title>
<h1>SafeShop - fixed build</h1>
<h2>Login</h2>
<form method="post" action="/login">
  <input name="username" placeholder="username">
  <input name="password" placeholder="password" type="text">
  <button>Log in</button>
</form>
<h2>Product search</h2>
<form method="get" action="/search">
  <input name="q" placeholder="e.g. mouse">
  <button>Search</button>
</form>
<h2>Product lookup by id</h2>
<form method="get" action="/product">
  <input name="id" placeholder="1">
  <button>Look up</button>
</form>
<hr>
{body}
"""


def render(body=""):
    return PAGE.format(body=body).encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "SafeShop/1.0"

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/":
            self._send(200, render())
        elif parsed.path == "/search":
            self._send(200, render(self.search(params.get("q", [""])[0])))
        elif parsed.path == "/product":
            code, body = self.product(params.get("id", [""])[0])
            self._send(code, render(body))
        else:
            self._send(404, render("<p>not found</p>"))

    def do_POST(self):
        if self.path != "/login":
            self._send(404, render("<p>not found</p>"))
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        self._send(200, render(self.login(form.get("username", [""])[0],
                                          form.get("password", [""])[0])))

    # -------------------------------------------------------------- #
    #  SAFE DATA ACCESS - every value travels as a bound parameter   #
    # -------------------------------------------------------------- #
    def login(self, username, password):
        try:
            conn = db()
            row = conn.execute(
                "SELECT id, username, role FROM users "
                "WHERE username = ? AND password = ?",
                (username, password),
            ).fetchone()
            conn.close()
        except sqlite3.Error as exc:
            print(f"[fixed] login db error: {exc}", file=sys.stderr)
            return "<p>Sorry, something went wrong.</p>"
        # Note: a real system would verify a password *hash* (bcrypt/argon2);
        # kept as a direct compare here so the two builds stay diff-able.
        if row:
            return (f"<p>Welcome back, <b>{html.escape(row[1])}</b> "
                    f"(role: {html.escape(row[2])}).</p>")
        return "<p>Login failed.</p>"

    def search(self, q):
        if len(q) > MAX_SEARCH_LEN:
            return "<p>Search term too long.</p>"
        try:
            conn = db()
            rows = conn.execute(
                "SELECT id, name, price FROM products WHERE name LIKE ?",
                (f"%{q}%",),
            ).fetchall()
            conn.close()
        except sqlite3.Error as exc:
            print(f"[fixed] search db error: {exc}", file=sys.stderr)
            return "<p>Sorry, something went wrong.</p>"
        out = [f"<p>{len(rows)} result(s) for <code>{html.escape(q)}</code>:</p><ul>"]
        for r in rows:
            out.append(f"<li>#{html.escape(str(r[0]))} - "
                       f"{html.escape(str(r[1]))} - {html.escape(str(r[2]))}</li>")
        out.append("</ul>")
        return "".join(out)

    def product(self, pid):
        if not ID_RE.match(pid):
            return 400, "<p>Invalid product id.</p>"
        try:
            conn = db()
            row = conn.execute(
                "SELECT id, name, description FROM products WHERE id = ?",
                (int(pid),),
            ).fetchone()
            conn.close()
        except sqlite3.Error as exc:
            print(f"[fixed] product db error: {exc}", file=sys.stderr)
            return 500, "<p>Sorry, something went wrong.</p>"
        if row:
            return 200, (f"<p>Product #{html.escape(str(row[0]))}: "
                         f"<b>{html.escape(str(row[1]))}</b><br>"
                         f"{html.escape(str(row[2]))}</p>")
        return 200, "<p>No such product.</p>"

    def log_message(self, *_):
        pass


def main():
    if not os.path.exists(DB_PATH):
        raise SystemExit("db/app.db missing - run: python3 db/seed.py")
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[fixed] http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
