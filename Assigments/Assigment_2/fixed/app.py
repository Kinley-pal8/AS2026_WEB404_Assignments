#!/usr/bin/env python3
"""
WEB404 Assignment 2 - JWT Authentication Attacks - FIXED build.

Same hand-rolled JWT format and the same three endpoints as the vulnerable
build; only decode_secure() and the secret changed. Defences:

  1. Algorithm whitelisting - the server decides which algorithm to verify
     with (HS256, always); it never trusts the "alg" field in the token.
  2. Strong secret - 256 bits of randomness instead of a dictionary word.
     (In production this would live in an environment variable / secret
     manager and be rotated periodically, not hardcoded in source.)
  3. Mandatory, server-side expiry enforcement on every request.
  4. Constant-time signature comparison (hmac.compare_digest), same as the
     vulnerable build - the bug there was never reaching the comparison.

Further hardening worth doing in a real system, out of scope here: short
access-token expiry backed by a separate refresh-token flow, and a
persisted deny-list for logout/revocation (JWTs are stateless by design).

    python3 fixed/app.py     # serves http://127.0.0.1:6002

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

PORT = int(os.environ.get("PORT", "6002"))

# Defence #2: a long, random, non-guessable secret.
SECRET = "2ca33626b2b5e16d6d6362aa94cb74f1dceeb2f97a62329065b2d315b9f3a5ab"

# Defence #3: short-lived tokens.
EXP_SECONDS = 120

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


def decode_secure(token: str) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
    except Exception:
        raise InvalidToken("malformed token")

    # Defence #1: the algorithm is pinned by the server, never read from the
    # attacker-controlled token. alg=none (or anything else) is rejected here.
    if header.get("alg") != "HS256":
        raise InvalidToken("unsupported alg")

    try:
        sig = b64url_decode(sig_b64)
    except Exception:
        raise InvalidToken("malformed signature")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise InvalidToken("bad signature")

    payload = json.loads(b64url_decode(payload_b64))

    # Defence #3: expiry is mandatory, not optional.
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or time.time() >= exp:
        raise InvalidToken("expired")

    return payload


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>SafeAuth (fixed)</title>
<h1>SafeAuth - fixed JWT build</h1>
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
    server_version = "SafeAuth/1.0"

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
            "exp": int(time.time()) + EXP_SECONDS,
        }
        return 200, {"token": encode(payload), "role": user["role"]}

    def account(self, auth_header):
        if not auth_header or not auth_header.startswith("Bearer "):
            return 401, {"error": "missing bearer token"}
        token = auth_header[len("Bearer "):].strip()
        try:
            payload = decode_secure(token)
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
    print(f"[fixed] http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
