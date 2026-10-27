# Assignment 5 - Server-Side Template Injection (SSTI)

WEB404 Secure Coding Practices - Topic 5

"CardForge", a greeting-card preview feature that renders user input through
Jinja2. The vulnerable build splices user input into the template **source**,
so the engine runs it as template code (detection, secret disclosure, and
remote code execution). The fixed build binds user input as template **data**,
turns on auto-escaping, and runs in a sandboxed environment. See
[report.md](report.md) for the full write-up.

> The `vulnerable/` app is intentionally insecure and will execute
> attacker-supplied shell commands. Run it on `127.0.0.1` only. Never deploy
> it or expose it to a network.

## Requirements

Python 3.8+, `Jinja2` (`pip install jinja2`), and `curl`. `bash` is needed for
the exploit scripts. No browser step is required - every technique is fully
provable with `curl`, because SSTI executes entirely on the server.

## Layout

| Path | Purpose |
| --- | --- |
| `vulnerable/app.py` | Insecure build: user input concatenated into the template source (`env.from_string("..." + body)`), plain `Environment`, `config` in scope. Port 9001. |
| `fixed/app.py` | Hardened build: user input bound as data to a fixed template, `SandboxedEnvironment`, auto-escaping, no secrets in render scope. Port 9002. |
| `exploits/01-ssti-detect.sh` | `{{ 7*7 }}` -> `49` confirms input is evaluated as code. |
| `exploits/02-config-leak.sh` | `{{ config }}` dumps `SECRET_KEY` / `DB_PASSWORD` from the render scope. |
| `exploits/03-rce.sh` | `{{ cycler.__init__.__globals__.os.popen('id').read() }}` runs a shell command (RCE). |
| `exploits/04-sandbox-check.sh` | Offline proof that the fixed build's `SandboxedEnvironment` refuses the RCE gadget with `SecurityError`. |
| `exploits/run-demo.sh` | Starts both apps, runs all techniques against both, saves a transcript. |
| `evidence/` | Demo transcript + where to drop your Burp Suite / browser screenshots. |

## Quick start

```bash
cd Assigments/Assigment_5
bash exploits/run-demo.sh
```

The transcript is printed and also written to `evidence/demo-output.txt`.

## Run it manually (for Burp Suite)

```bash
python3 vulnerable/app.py     # terminal 1 -> http://127.0.0.1:9001
python3 fixed/app.py          # terminal 2 -> http://127.0.0.1:9002
```

Individual exploit scripts take a `TARGET` environment variable:

```bash
TARGET=http://127.0.0.1:9001 bash exploits/01-ssti-detect.sh   # works
TARGET=http://127.0.0.1:9002 bash exploits/01-ssti-detect.sh   # blocked
```

## The fix in one line

`vulnerable/app.py` runs `env.from_string("<div class='card'>" + body +
"</div>").render(config=CONFIG, user=USER)` - the user's text becomes template
**code**. `fixed/app.py` renders a constant template, `"<div
class='card'>{{ body }}</div>"`, with `body` bound as **data**, under a
`SandboxedEnvironment(autoescape=...)` with no secrets in scope.
`diff vulnerable/app.py fixed/app.py` shows every change.
