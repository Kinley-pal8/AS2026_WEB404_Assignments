# Assignment 1 - SQL Injection: Build & Defend

WEB404 Secure Coding Practices · Topic 1

A deliberately vulnerable web app with a database-backed login and product
search, four working SQL-injection exploits, and a hardened build that blocks
every one of them. See [report.md](report.md) for the full write-up.

> ⚠️ The `vulnerable/` app is intentionally insecure. Run it on `127.0.0.1`
> only. Never deploy it or expose it to a network.

## Requirements

Python 3.8+ and `curl`. **No third-party packages** - everything uses the
standard library (`http.server`, `sqlite3`). `bash` is needed for the exploit
scripts.

## Layout

| Path | Purpose |
| --- | --- |
| `db/seed.py` | Creates `db/app.db` (3 users, 4 products). Overwrites on each run. |
| `vulnerable/app.py` | Insecure build - SQL built by string interpolation. Port 5001. |
| `fixed/app.py` | Hardened build - parameterised queries + validation + least privilege. Port 5002. |
| `exploits/01-auth-bypass.sh` | Boolean-based authentication bypass on `POST /login`. |
| `exploits/02-union-based.sh` | UNION-based extraction of the `users` table via `GET /search`. |
| `exploits/03-error-based.sh` | Error-message disclosure of query structure. |
| `exploits/04-boolean-blind.sh` | Blind boolean extraction of the admin password via `GET /product`. |
| `exploits/run-demo.sh` | Seeds, starts both apps, runs all four exploits against both, saves a transcript. |
| `evidence/` | Demo transcript + where to drop your Burp/ZAP screenshots. |

## Quick start

```bash
cd Assigments/Assigment_1

# One command: seed, start both apps, run every exploit against both builds.
bash exploits/run-demo.sh
```

The transcript is printed and also written to `evidence/demo-output.txt`.

## Run it manually (for Burp Suite / OWASP ZAP)

```bash
python3 db/seed.py

python3 vulnerable/app.py     # terminal 1 -> http://127.0.0.1:5001
python3 fixed/app.py          # terminal 2 -> http://127.0.0.1:5002
```

Open `http://127.0.0.1:5001/` in a browser with Burp/ZAP proxying, exercise the
three forms, then send the requests to Repeater and paste the payloads from
`report.md` §3. Repeat against `:5002` to show they no longer work.

Individual exploit scripts take a `TARGET` environment variable:

```bash
TARGET=http://127.0.0.1:5001 bash exploits/02-union-based.sh   # works
TARGET=http://127.0.0.1:5002 bash exploits/02-union-based.sh   # blocked
```

## The fix in one line

`vulnerable/app.py` builds SQL like
`f"... WHERE username = '{username}'"`; `fixed/app.py` uses
`conn.execute("... WHERE username = ?", (username,))` so input is sent as a
bound parameter and can never be parsed as SQL. `diff vulnerable/app.py
fixed/app.py` shows every change.
