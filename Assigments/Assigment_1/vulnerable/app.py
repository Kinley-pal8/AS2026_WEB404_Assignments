#!/usr/bin/env python3
"""
WEB404 Assignment 1 - SQL Injection - VULNERABLE build.

Every SQL statement below is assembled by pasting user input straight into the
query text with an f-string. This is intentionally insecure. Run on localhost
only.

    python3 db/seed.py            # once, to (re)create db/app.db
    python3 vulnerable/app.py     # serves http://127.0.0.1:5001

Endpoints
    GET  /                landing page with the three forms
    POST /login           username + password   -> boolean-based auth bypass
    GET  /search?q=       product name search   -> UNION-based data extraction
    GET  /product?id=     numeric id lookup     -> boolean-blind + error-based
"""
import html
import os
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "app.db")
PORT = int(os.environ.get("PORT", "5001"))


def db():
    # A full read/write handle with no restrictions - see the fixed build for
    # how a least-privilege (read-only) connection limits the blast radius.
    return sqlite3.connect(DB_PATH)


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>VulnShop (vulnerable)</title>
<h1>VulnShop - vulnerable build</h1>
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
    server_version = "VulnShop/1.0"

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
            self._send(200, render(self.product(params.get("id", [""])[0])))
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

    # ------------------------------------------------------------------ #
    #  VULNERABLE DATA ACCESS - user input is concatenated into the SQL  #
    # ------------------------------------------------------------------ #
    def login(self, username, password):
        query = (
            "SELECT id, username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        try:
            conn = db()
            row = conn.execute(query).fetchone()
            conn.close()
        except sqlite3.Error as exc:
            # Raw database error echoed to the client -> error-based SQLi.
            return (f"<pre>SQL error: {html.escape(str(exc))}\n"
                    f"query:     {html.escape(query)}</pre>")
        if row:
            return (f"<p>Welcome back, <b>{html.escape(row[1])}</b> "
                    f"(role: {html.escape(row[2])}).</p>")
        return "<p>Login failed.</p>"

    def search(self, q):
        query = ("SELECT id, name, price FROM products "
                 f"WHERE name LIKE '%{q}%'")
        try:
            conn = db()
            rows = conn.execute(query).fetchall()
            conn.close()
        except sqlite3.Error as exc:
            return (f"<pre>SQL error: {html.escape(str(exc))}\n"
                    f"query:     {html.escape(query)}</pre>")
        out = [f"<p>{len(rows)} result(s) for <code>{html.escape(q)}</code>:</p><ul>"]
        for r in rows:
            out.append(f"<li>#{html.escape(str(r[0]))} - "
                       f"{html.escape(str(r[1]))} - {html.escape(str(r[2]))}</li>")
        out.append("</ul>")
        return "".join(out)

    def product(self, pid):
        # Numeric context: the value is not wrapped in quotes.
        query = f"SELECT id, name, description FROM products WHERE id = {pid}"
        try:
            conn = db()
            row = conn.execute(query).fetchone()
            conn.close()
        except sqlite3.Error as exc:
            return (f"<pre>SQL error: {html.escape(str(exc))}\n"
                    f"query:     {html.escape(query)}</pre>")
        if row:
            return (f"<p>Product #{html.escape(str(row[0]))}: "
                    f"<b>{html.escape(str(row[1]))}</b><br>{html.escape(str(row[2]))}</p>")
        return "<p>No such product.</p>"

    def log_message(self, *_):
        pass


def main():
    if not os.path.exists(DB_PATH):
        raise SystemExit("db/app.db missing - run: python3 db/seed.py")
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[vulnerable] http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
