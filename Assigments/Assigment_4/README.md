# Assignment 4 - Cross-Site Scripting (XSS) + CSP

WEB404 Secure Coding Practices - Topic 4

"QuickNotes", a tiny noticeboard with all three XSS types (reflected,
stored, DOM-based) in one page, plus a hardened build with output encoding,
a strict CSP, and secure cookie attributes. See [report.md](report.md) for
the full write-up.

> The `vulnerable/` app is intentionally insecure. Run it on `127.0.0.1`
> only. Never deploy it or expose it to a network.

## Requirements

Python 3.8+ and `curl`. No third-party packages - encoding uses the
stdlib `html` module. `bash` is needed for the exploit scripts. A real
browser (any) is needed for one manual step - see below.

## Layout

| Path | Purpose |
| --- | --- |
| `vulnerable/app.py` | Insecure build: unescaped reflected search, unescaped stored notes, `innerHTML` DOM sink, no CSP, non-HttpOnly cookie. Port 8001. |
| `fixed/app.py` | Hardened build: `html.escape()` on every output, `textContent` DOM sink, strict CSP, `HttpOnly`/`SameSite` cookie. Port 8002. |
| `exploits/01-reflected-xss.sh` | Reflected XSS via `GET /search?q=`. |
| `exploits/02-stored-xss.sh` | Stored XSS via `POST /notes` + `GET /`. |
| `exploits/03-cookie-theft.sh` | Checks whether the session cookie is readable from JS and, if so, simulates the exfiltration a payload would perform. |
| `exploits/04-dom-xss-check.sh` | Confirms the client-side `innerHTML`/`textContent` sink, and prints the URL to test by hand. |
| `exploits/05-csp-and-cookie-flags.sh` | Checks the `Content-Security-Policy` and `Set-Cookie` headers. |
| `exploits/run-demo.sh` | Starts both apps, runs all five checks against both, saves a transcript. |
| `evidence/` | Demo transcript + where to drop your Burp Suite / browser screenshots. |

## Quick start

```bash
cd Assigments/Assigment_4
bash exploits/run-demo.sh
```

The transcript is printed and also written to `evidence/demo-output.txt`.

**curl cannot execute JavaScript**, so it can prove reflected/stored XSS (the
raw, unescaped payload appears in the HTML - anything a browser would then
render and run) and it can prove the DOM-based sink is present in the source,
but it cannot pop an actual alert box for the DOM case. `run-demo.sh` prints
the exact URL for that - open it in any browser:

```
http://127.0.0.1:8001/#<img src=x onerror=alert(document.cookie)>
```

against `:8001` (alert fires) and `:8002` (it does not - the fragment is
never sent to the server either way, but the fixed page's `textContent` sink
never parses it as markup).

## Run it manually (for Burp Suite)

```bash
python3 vulnerable/app.py     # terminal 1 -> http://127.0.0.1:8001
python3 fixed/app.py          # terminal 2 -> http://127.0.0.1:8002
```

Individual exploit scripts take a `TARGET` environment variable:

```bash
TARGET=http://127.0.0.1:8001 bash exploits/01-reflected-xss.sh   # works
TARGET=http://127.0.0.1:8002 bash exploits/01-reflected-xss.sh   # blocked
```

## The fix in one line

`vulnerable/app.py` writes `f"<b>{n['author']}</b>: {n['message']}"` and
`document.getElementById('welcome').innerHTML = 'Welcome, ' + name + '!'`.
`fixed/app.py` writes `f"<b>{html.escape(n['author'])}</b>: {html.escape(n['message'])}"`,
uses `textContent` instead of `innerHTML` client-side, sends a strict
`Content-Security-Policy` with no `'unsafe-inline'`, and sets
`HttpOnly; SameSite=Lax` on the session cookie. `diff vulnerable/app.py
fixed/app.py` shows every change.
