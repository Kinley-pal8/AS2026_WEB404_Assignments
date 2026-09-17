#!/usr/bin/env python3
"""
WEB404 Assignment 3 - SSRF + Access Control - FIXED build.

Same "URL preview" feature as the vulnerable build. Four independent
defences, each closing one of the vulnerable build's four gaps:

  1. Scheme allow-list - only http/https are fetched; file:// (and anything
     else) is rejected before any connection is attempted.
  2. Destination validation by RESOLVED IP, not by hostname string.
     validate_url() resolves the hostname with getaddrinfo() and rejects the
     request if ANY returned address is private, loopback, link-local,
     reserved, multicast, or unspecified. Checking the numeric address
     (ipaddress.ip_address(...).is_private/.is_loopback/...) instead of
     string-matching the hostname is what also defeats obfuscated literals
     like "127.1", "2130706433" or "0x7f000001" - they all resolve to the
     same 127.0.0.1, which the check catches regardless of how it was
     spelled. It also covers the real cloud metadata address,
     169.254.169.254, because 169.254.0.0/16 is link-local.
  3. Redirects are never followed automatically - a NoRedirect opener turns
     any 3xx response into an error instead of silently issuing a second
     request. This is what stops a URL that validates cleanly (an allowed,
     public host) from being used to hop into an internal address via its
     Location header.
  4. Authorization - POST /preview requires a valid session obtained from
     POST /login. The feature is no longer usable anonymously.

    python3 fixed/app.py     # serves http://127.0.0.1:7002

Endpoints
    GET  /            landing page
    POST /login       username + password -> {"token": "..."}
    POST /preview     Authorization: Bearer <token>, url=<...> -> preview JSON
"""
import ipaddress
import json
import os
import secrets
import socket
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "7002"))
SNIPPET_LEN = 500

ALLOWED_SCHEMES = {"http", "https"}

USERS = {"alice": "alice-pass"}
SESSIONS: dict[str, str] = {}  # token -> username


class SSRFBlocked(Exception):
    pass


def resolve_all_ips(hostname: str, port: int) -> set[str]:
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"could not resolve host: {exc}")
    return {info[4][0] for info in infos}


def is_public_address(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def validate_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFBlocked(f"scheme '{parsed.scheme}' is not allowed (only http/https)")
    if not parsed.hostname:
        raise SSRFBlocked("URL has no hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    for ip in resolve_all_ips(parsed.hostname, port):
        if not is_public_address(ip):
            raise SSRFBlocked(f"'{parsed.hostname}' resolves to non-public address {ip}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # refuse to follow - the caller gets the 3xx as an error


_opener = urllib.request.build_opener(NoRedirect)


def fetch_preview_secure(url: str) -> dict:
    validate_url(url)
    with _opener.open(url, timeout=5) as resp:
        body = resp.read(SNIPPET_LEN)
        return {
            "requested_url": url,
            "status": resp.status,
            "content_type": resp.headers.get("Content-Type"),
            "snippet": body.decode("utf-8", "replace"),
        }


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>LinkPeek (fixed)</title>
<h1>LinkPeek - fixed build</h1>
<p>Log in, then paste a URL. Only public http(s) destinations are fetched, and
redirects are never followed automatically.</p>
<h2>Login (browser test)</h2>
<form id="lf">
  <input name="username" placeholder="username">
  <input name="password" placeholder="password" type="text">
  <button>Log in</button>
</form>
<pre id="out"></pre>
<script>
document.getElementById('lf').onsubmit = async (e) => {{
  e.preventDefault();
  const fd = new URLSearchParams(new FormData(e.target));
  const r = await fetch('/login', {{method: 'POST', body: fd}});
  document.getElementById('out').textContent = await r.text();
}};
</script>
"""


def bearer_token(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    return auth_header[len("Bearer "):].strip()


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
        parsed_path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())

        if parsed_path == "/login":
            username, password = form.get("username", [""])[0], form.get("password", [""])[0]
            if USERS.get(username) != password:
                self._json(401, {"error": "invalid credentials"})
                return
            token = secrets.token_hex(16)
            SESSIONS[token] = username
            self._json(200, {"token": token})
            return

        if parsed_path == "/preview":
            token = bearer_token(self.headers.get("Authorization"))
            if token not in SESSIONS:
                self._json(401, {"error": "login required"})
                return
            url = form.get("url", [""])[0]
            if not url:
                self._json(400, {"error": "url is required"})
                return
            try:
                self._json(200, fetch_preview_secure(url))
            except SSRFBlocked as exc:
                self._json(400, {"error": str(exc)})
            except urllib.error.HTTPError as exc:
                self._json(502, {"error": f"fetch blocked: server returned HTTP {exc.code} "
                                          f"(redirects are not followed)"})
            except (urllib.error.URLError, ValueError, ConnectionError) as exc:
                self._json(502, {"error": f"fetch failed: {exc}"})
            return

        self._json(404, {"error": "not found"})

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
