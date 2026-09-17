#!/usr/bin/env python3
"""
WEB404 Assignment 2 - JWT Authentication Attacks - VULNERABLE build.

A hand-rolled JWT implementation (header.payload.signature, HS256) built from
the standard library only, so every design decision is visible instead of
hidden inside a library. Three vulnerabilities live in decode_insecure():

  1. The algorithm is read from the token's OWN header. A token that claims
     alg=none is trusted with no signature check at all.
  2. The signing secret is short and dictionary-guessable.
  3. The "exp" claim is never checked, so an expired (or forever-valid)
     token is accepted indefinitely.

Run on localhost only.

    python3 vulnerable/app.py     # serves http://127.0.0.1:6001

Endpoints
    GET  /            landing page
    POST /login       username + password -> {"token": "...", "role": "..."}
    GET  /account      Authorization: Bearer <token> -> account JSON
"""
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "6001"))

# Vulnerability #2: short, common, dictionary-guessable secret.
SECRET = "secret123"

USERS = {
    "admin": {"password": "Adm1n_2024!", "role": "admin"},
    "alice": {"password": "alice-pass", "role": "customer"},
    "bob":   {"password": "bob-pass",   "role": "customer"},
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def encode(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
    sig = hmac.new(SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(sig)}"


class InvalidToken(Exception):
    pass


def decode_insecure(token: str) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except Exception:
        raise InvalidToken("malformed token")

    # Vulnerability #1: alg comes from the attacker-controlled token itself.
    alg = header.get("alg")
    if alg == "none":
        return payload
    if alg != "HS256":
        raise InvalidToken("unsupported alg")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64url_decode(sig_b64)):
        raise InvalidToken("bad signature")

    # Vulnerability #3: "exp" is never read here.
    return payload


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>VulnAuth (vulnerable)</title>
<h1>VulnAuth - vulnerable JWT build</h1>
<p>API only. Log in to get a token, then call /account with it:</p>
<pre>
curl -s {target}/login --data-urlencode username=alice --data-urlencode password=alice-pass
curl -s {target}/account -H "Authorization: Bearer &lt;token&gt;"
</pre>
<h2>Login (browser test)</h2>
<form id="f">
  <input name="username" placeholder="username">
  <input name="password" placeholder="password" type="text">
  <button>Log in</button>
</form>
<pre id="out"></pre>
<script>
document.getElementById('f').onsubmit = async (e) => {{
  e.preventDefault();
  const fd = new URLSearchParams(new FormData(e.target));
  const r = await fetch('/login', {{method: 'POST', body: fd}});
  document.getElementById('out').textContent = await r.text();
}};
</script>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnAuth/1.0"

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
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self._html(200, PAGE.format(target=f"http://127.0.0.1:{PORT}").encode())
        elif parsed.path == "/account":
            code, obj = self.account(self.headers.get("Authorization"))
            self._json(code, obj)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/login":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        code, obj = self.login(form.get("username", [""])[0], form.get("password", [""])[0])
        self._json(code, obj)

    def login(self, username, password):
        user = USERS.get(username)
        if not user or user["password"] != password:
            return 401, {"error": "invalid credentials"}
        payload = {
            "sub": username,
            "role": user["role"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        }
        return 200, {"token": encode(payload), "role": user["role"]}

    def account(self, auth_header):
        if not auth_header or not auth_header.startswith("Bearer "):
            return 401, {"error": "missing bearer token"}
        token = auth_header[len("Bearer "):].strip()
        try:
            payload = decode_insecure(token)
        except InvalidToken as exc:
            return 401, {"error": str(exc)}
        data = {"sub": payload.get("sub"), "role": payload.get("role")}
        if payload.get("role") == "admin":
            data["admin_secret"] = "vault override code: 7742-XQ"
        else:
            data["note"] = "customer account - nothing secret here"
        return 200, data

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
