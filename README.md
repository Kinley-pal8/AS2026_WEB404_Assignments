# WEB404 - Secure Coding Practices Coursework

Five build-and-defend assignments for the WEB404 Secure Coding Practices
module. Each one ships a deliberately vulnerable web app, working exploits
against it, a hardened build that blocks those exploits, and a report
explaining the mechanism and the fix. See
[Assigments/Description.md](Assigments/Description.md) for the official
topic descriptions and grading criteria.

> Every `vulnerable/` app in this repo is intentionally insecure. Run
> everything on `127.0.0.1` only - nothing here should ever be deployed or
> exposed to a network.

## Assignments

| # | Topic | Status | Folder |
| - | ----- | ------ | ------ |
| 1 | SQL Injection - Build & Defend | Done | [Assigments/Assigment_1](Assigments/Assigment_1) |
| 2 | JWT Authentication Attacks | Done | [Assigments/Assigment_2](Assigments/Assigment_2) |
| 3 | SSRF + Access Control | Done | [Assigments/Assigment_3](Assigments/Assigment_3) |
| 4 | Cross-Site Scripting (XSS) + CSP | Done | [Assigments/Assigment_4](Assigments/Assigment_4) |
| 5 | Server-Side Template Injection (SSTI) | Not started | Assigments/Assigment_5 |

### 1. SQL Injection - Build & Defend

"VulnShop": a login form and product search backed by SQLite. Demonstrates
boolean-based auth bypass, UNION-based data extraction, error-based
disclosure, and blind boolean extraction, then fixes all four with
parameterised queries, input validation, a read-only DB handle, and generic
error handling.

### 2. JWT Authentication Attacks

"VulnAuth": a hand-rolled JWT login/session API (stdlib only, no PyJWT).
Demonstrates an `alg:none` signature bypass, offline brute force of a weak
HMAC secret, and expired-token replay, then fixes all three with algorithm
whitelisting, a strong random secret, and mandatory expiry enforcement.

### 3. SSRF + Access Control

"LinkPeek": a URL-preview feature that fetches whatever link it's given.
Demonstrates SSRF into a simulated internal admin API, a simulated
cloud-metadata endpoint, a redirect-chained bypass, and local file
disclosure via `file://`, plus a missing-authorization check, then fixes all
five with resolved-IP destination validation, a scheme allow-list, disabled
redirect-following, and required login.

### 4. Cross-Site Scripting (XSS) + CSP

"QuickNotes": a noticeboard carrying all three XSS types on one page -
reflected search, stored notes, and a DOM-based `innerHTML` sink - plus
session cookie theft as the usual real-world payoff. Fixed with
context-aware output encoding, a `textContent` DOM sink, a strict
Content-Security-Policy, and `HttpOnly`/`SameSite` cookie attributes.

### 5. Server-Side Template Injection (SSTI)

Not built yet. Per the brief: render user input through a server-side
template engine (Jinja2/Twig/FreeMarker), exploit it toward RCE or data
disclosure, then remediate with sandboxing/logic-less templates and strict
separation of user input from template logic.

## Layout convention

Each assignment folder follows the same shape:

| Path | Purpose |
| --- | --- |
| `README.md` | How to run that assignment's apps and exploits. |
| `report.md` | The graded write-up: mechanism, exploitation, fix, verification. |
| `vulnerable/` | The insecure build. |
| `fixed/` | The hardened build - same features, only the security-relevant code differs. |
| `exploits/` | Scripts that attack both builds and print a clear pass/fail per technique. |
| `exploits/run-demo.sh` | Boots everything needed, runs every exploit against both builds, saves a transcript. |
| `evidence/` | The auto-generated transcript, plus a checklist of Burp Suite / browser screenshots still needed for the report. |

Every vulnerable/fixed pair is a small, dependency-free Python 3 program
(standard library only) so grading needs nothing beyond Python 3, `curl`,
and `bash` - no `pip install`, no network access, no external services.

## Quick start

```bash
cd Assigments/Assigment_<N>
bash exploits/run-demo.sh
```

Each `run-demo.sh` seeds any state it needs, starts both the vulnerable and
fixed apps on fixed local ports, runs every exploit against both, and writes
a transcript to that assignment's `evidence/demo-output.txt`. See each
assignment's own `README.md` for manual run steps (useful for driving the
apps through Burp Suite) and its `evidence/README.md` for the specific
screenshots still needed to complete the report.
