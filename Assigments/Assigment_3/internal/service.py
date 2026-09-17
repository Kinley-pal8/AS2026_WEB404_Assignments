#!/usr/bin/env python3
"""
Simulated backend services used by BOTH the vulnerable and fixed apps to
demonstrate SSRF impact. Neither of these is "the app under test" - they
stand in for infrastructure a real deployment would keep unreachable from
the public internet.

  127.0.0.1:7099  "internal admin API" - in a real deployment this would sit
    on a private subnet, reachable only from inside the network, never from
    the public internet. Also serves a path shaped like the real AWS EC2
    metadata service to stand in for it (the real one lives at the
    link-local address 169.254.169.254, which we don't bind here - see
    report.md section 2 for why, and how the fixed build's IP check still
    covers it).

  127.0.0.2:7050  "external site" - stands in for an internet-hosted site
    the fetch feature is legitimately allowed to reach, which happens to
    have an open redirect. Used to show that validating only the URL the
    user submitted is not enough if the server then follows redirects.

Both addresses are loopback (the whole 127.0.0.0/8 block is loopback on
Linux) so no network configuration is required, but the two ports model a
network boundary that would be firewalled apart in production: nothing
outside this machine can reach either of them.

    python3 internal/service.py
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

INTERNAL_HOST, INTERNAL_PORT = "127.0.0.1", 7099
EXTERNAL_HOST, EXTERNAL_PORT = "127.0.0.2", 7050


class InternalHandler(BaseHTTPRequestHandler):
    server_version = "InternalAdmin/1.0"

    def do_GET(self):
        if self.path == "/internal/admin":
            body = json.dumps({
                "service": "internal-admin-api",
                "note": "reachable only from inside the private network in a real deployment",
                "db_password": "Cluster_Root_Pw!2024",
                "support_override_token": "INTOK-8842-ADMIN",
            }, indent=2).encode()
        elif self.path.startswith("/latest/meta-data/iam/security-credentials"):
            body = json.dumps({
                "service": "fake-cloud-metadata (models the real 169.254.169.254)",
                "Code": "Success",
                "AccessKeyId": "AKIAFAKEDEMOACCESSKEY",
                "SecretAccessKey": "fAkeDemoSecretAccessKey1234567890abcd",
                "Token": "FAKE.SESSION.TOKEN",
                "Expiration": "2099-01-01T00:00:00Z",
            }, indent=2).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class ExternalHandler(BaseHTTPRequestHandler):
    server_version = "ExternalSite/1.0"

    def do_GET(self):
        if self.path == "/bounce":
            self.send_response(302)
            self.send_header("Location", f"http://{INTERNAL_HOST}:{INTERNAL_PORT}/internal/admin")
            self.end_headers()
            return
        body = b"<html><body>a perfectly normal external website</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    internal = HTTPServer((INTERNAL_HOST, INTERNAL_PORT), InternalHandler)
    external = HTTPServer((EXTERNAL_HOST, EXTERNAL_PORT), ExternalHandler)
    Thread(target=internal.serve_forever, daemon=True).start()
    print(f"[internal] http://{INTERNAL_HOST}:{INTERNAL_PORT}  (simulated internal admin API + metadata)")
    print(f"[external] http://{EXTERNAL_HOST}:{EXTERNAL_PORT}  (simulated external site with an open redirect)")
    try:
        external.serve_forever()
    except KeyboardInterrupt:
        internal.shutdown()


if __name__ == "__main__":
    main()
