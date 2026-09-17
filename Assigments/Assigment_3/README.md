# Assignment 3 - SSRF + Access Control

WEB404 Secure Coding Practices - Topic 3

A "URL preview" feature (paste a link, the server fetches and shows a
snippet) with four working SSRF-family exploits plus a missing-authorization
check, and a hardened build that blocks all of them. See
[report.md](report.md) for the full write-up.

> The `vulnerable/` app is intentionally insecure. Run it on `127.0.0.1`
> only. Never deploy it or expose it to a network.

## Requirements

Python 3.9+ (uses bare `dict[...]`/`set[...]` type hints) and `curl`. No
third-party packages - the fetch and validation logic use only
`urllib`/`socket`/`ipaddress`. `bash` is needed for the exploit scripts.

## Layout

| Path | Purpose |
| --- | --- |
| `internal/service.py` | Simulated backend: an "internal admin API" + fake cloud-metadata path on `127.0.0.1:7099`, and an "external site" with an open redirect on `127.0.0.2:7050`. Neither is the app under test. |
| `vulnerable/app.py` | Insecure build. Fetches any URL, any scheme, follows redirects, no login required. Port 7001. |
| `fixed/app.py` | Hardened build. Scheme allow-list, resolved-IP validation, no redirect following, login required. Port 7002. |
| `exploits/01-internal-admin.sh` | Direct SSRF to the simulated internal admin API. |
| `exploits/02-cloud-metadata.sh` | SSRF to a simulated cloud-metadata endpoint (models AWS's 169.254.169.254). |
| `exploits/03-redirect-bypass.sh` | Fetches an "allowed-looking" external URL that redirects into the internal API. |
| `exploits/03b-redirect-handler-proof.py` | Isolated proof that the fixed build's no-redirect control works on its own merits (see report.md 4.3). |
| `exploits/04-file-scheme.sh` | Local file disclosure via `file://`. |
| `exploits/05-auth-required.sh` | Confirms the feature is usable with no login on the vulnerable build, and isn't on the fixed one. |
| `exploits/run-demo.sh` | Starts everything, runs every check against both builds, saves a transcript. |
| `evidence/` | Demo transcript + where to drop your Burp Suite screenshots. |

## Quick start

```bash
cd Assigments/Assigment_3
bash exploits/run-demo.sh
```

The transcript is printed and also written to `evidence/demo-output.txt`.

## Run it manually (for Burp Suite)

```bash
python3 internal/service.py    # terminal 1 -> :7099 (internal) and :7050 (external)
python3 vulnerable/app.py      # terminal 2 -> http://127.0.0.1:7001
python3 fixed/app.py           # terminal 3 -> http://127.0.0.1:7002
```

```bash
# vulnerable: no login, any URL
curl -s http://127.0.0.1:7001/preview --data-urlencode "url=http://127.0.0.1:7099/internal/admin"

# fixed: log in first
token=$(curl -s http://127.0.0.1:7002/login --data-urlencode username=alice --data-urlencode password=alice-pass \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s http://127.0.0.1:7002/preview -H "Authorization: Bearer $token" \
  --data-urlencode "url=http://127.0.0.1:7099/internal/admin"
```

Individual exploit scripts take `TARGET` and (for the fixed build) `TOKEN`:

```bash
TARGET=http://127.0.0.1:7001 bash exploits/01-internal-admin.sh                    # works
TARGET=http://127.0.0.1:7002 TOKEN="$token" bash exploits/01-internal-admin.sh      # blocked
```

## The fix in one line

`vulnerable/app.py` calls `urllib.request.urlopen(url)` on whatever string it
is given, with no login required. `fixed/app.py` resolves the hostname first
and rejects the request unless every resolved IP is a public address
(`ipaddress.ip_address(ip).is_private/.is_loopback/.is_link_local/...`),
rejects any non-http(s) scheme, never follows redirects, and requires a
session from `POST /login` before it will fetch anything at all.
`diff vulnerable/app.py fixed/app.py` shows every change.
