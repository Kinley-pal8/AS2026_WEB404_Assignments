# Evidence

`demo-output.txt` is the auto-generated transcript from `bash exploits/run-demo.sh`
(every technique run against both the vulnerable :9001 and fixed :9002 builds,
plus the offline sandbox check).

## Screenshots to capture for the report

The grading rubric gives 2 marks for "quality of screenshots/evidence", and
this topic explicitly asks for "proof of successful template injection/RCE".
Capture these with Burp Suite (Proxy -> HTTP history / Repeater) and/or a
browser, and save them here with the filenames the report references.

| File | What it should show |
| --- | --- |
| `01-detect-vuln.png` | Burp Repeater `POST /preview` with `body={{ 7*7 }}` against `:9001` -> response contains `49`. |
| `01-detect-fixed.png` | Same request against `:9002` -> response contains the literal `{{ 7*7 }}`. |
| `02-config-vuln.png` | `POST /preview` with `body={{ config }}` against `:9001` -> response leaks `SECRET_KEY` / `DB_PASSWORD`. |
| `02-config-fixed.png` | Same against `:9002` -> literal `{{ config }}`, no secret. |
| `03-rce-vuln.png` | `POST /preview` with the `cycler...popen('id')` gadget against `:9001` -> response contains the `uid=...` output of the `id` command. |
| `03-rce-fixed.png` | Same against `:9002` -> literal payload text, no command output. |
| `04-sandbox.png` | Terminal running `bash exploits/04-sandbox-check.sh` -> plain `Environment` returns `uid=...`, `SandboxedEnvironment` raises `SecurityError`. |
| `diff.png` | `diff vulnerable/app.py fixed/app.py` in a terminal. |

## Reproducing

```bash
cd Assigments/Assigment_5
bash exploits/run-demo.sh          # regenerates demo-output.txt
```
