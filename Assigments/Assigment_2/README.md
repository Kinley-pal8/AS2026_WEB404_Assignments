# Assignment 2 - JWT Authentication Attacks

WEB404 Secure Coding Practices - Topic 2

A hand-rolled JWT login/session system with three working attacks, and a
hardened build that blocks all of them. See [report.md](report.md) for the
full write-up.

> The `vulnerable/` app is intentionally insecure. Run it on `127.0.0.1`
> only. Never deploy it or expose it to a network.

## Requirements

Python 3.8+ and `curl`. No third-party packages, no PyJWT - the JWT
encode/decode is implemented from scratch with `hashlib`/`hmac`/`base64`/`json`
so every check (or missing check) is visible in the source. `bash` is needed
for the exploit scripts.

## Layout

| Path | Purpose |
| --- | --- |
| `vulnerable/app.py` | Insecure build. Trusts the token's own `alg`, weak secret, no expiry check. Port 6001. |
| `fixed/app.py` | Hardened build. Pinned algorithm, strong secret, mandatory expiry. Port 6002. |
| `exploits/jwt_forge.py` | Shared helper: forge an `alg:none` token, sign a token with a chosen secret, brute-force a secret, decode a token without verifying it. |
| `exploits/wordlist.txt` | Small candidate-secret list used by the brute-force exploit. |
| `exploits/01-alg-none-bypass.sh` | Forges a signature-less token claiming `role=admin`. |
| `exploits/02-weak-secret-bruteforce.sh` | Recovers the signing secret offline from one captured token, then forges a new admin token with it. |
| `exploits/03-expired-token-replay.sh` | Replays a token whose `exp` claim is an hour in the past. |
| `exploits/run-demo.sh` | Starts both apps, runs all three exploits against both, saves a transcript. |
| `evidence/` | Demo transcript + where to drop your Burp Suite / jwt_tool screenshots. |

## Quick start

```bash
cd Assigments/Assigment_2
bash exploits/run-demo.sh
```

The transcript is printed and also written to `evidence/demo-output.txt`.

## Run it manually (for Burp Suite / jwt_tool)

```bash
python3 vulnerable/app.py     # terminal 1 -> http://127.0.0.1:6001
python3 fixed/app.py          # terminal 2 -> http://127.0.0.1:6002
```

```bash
# get a real token
curl -s http://127.0.0.1:6001/login --data-urlencode username=alice --data-urlencode password=alice-pass

# use it
curl -s http://127.0.0.1:6001/account -H "Authorization: Bearer <token>"
```

Paste a captured token into [jwt.io](https://jwt.io) or run it through
`jwt_tool` to inspect the header/payload, or feed it to
`exploits/jwt_forge.py decode <token>` for an offline, no-dependency decode.
Individual exploit scripts take a `TARGET` environment variable:

```bash
TARGET=http://127.0.0.1:6001 bash exploits/01-alg-none-bypass.sh   # works
TARGET=http://127.0.0.1:6002 bash exploits/01-alg-none-bypass.sh   # blocked
```

## The fix in one line

`vulnerable/app.py` decides how to verify a token by reading `alg` out of the
token itself (`if header.get("alg") == "none": return payload`) and never
checks `exp`. `fixed/app.py` always verifies with the one algorithm the
server issues (`if header.get("alg") != "HS256": raise`), uses a 256-bit
random secret instead of a dictionary word, and rejects any token whose `exp`
has passed. `diff vulnerable/app.py fixed/app.py` shows every change.
