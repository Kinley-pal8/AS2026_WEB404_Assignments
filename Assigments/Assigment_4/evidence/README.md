# Evidence

`demo-output.txt` is the auto-generated transcript from `bash exploits/run-demo.sh`
(every check run against both the vulnerable :8001 and fixed :8002 builds).

## Screenshots to capture for the report

The grading rubric gives 2 marks for "quality of screenshots/evidence", and
this topic explicitly asks for "proof-of-concept payloads" per XSS type.
Capture these with Burp Suite (Proxy -> HTTP history / Repeater) and a real
browser, and save them here with the filenames the report references.

| File | What it should show |
| --- | --- |
| `01-reflected-vuln.png` | Browser at `http://127.0.0.1:8001/search?q=<img src=x onerror=alert(document.cookie)>` -> an alert box showing the session cookie. |
| `01-reflected-fixed.png` | Same URL against `:8002` -> the literal text `<img src=x ...>` printed on the page, no alert. |
| `02-stored-vuln.png` | Post a note containing the payload via the form on `:8001`, then reload `/` -> the alert fires for every visitor with no further action. |
| `02-stored-fixed.png` | Same steps against `:8002` -> the note is displayed as literal text. |
| `03-cookie-vuln.png` | Browser DevTools Application/Storage tab on `:8001` showing the cookie has no `HttpOnly` flag, next to the `alert(document.cookie)` popup from either PoC above. |
| `03-cookie-fixed.png` | Same DevTools view on `:8002` showing `HttpOnly` is set. |
| `04-dom-vuln.png` | Browser at `http://127.0.0.1:8001/#<img src=x onerror=alert(document.cookie)>` -> alert box. Note in the URL bar / Network tab that no request was made carrying the payload (it's a fragment). |
| `04-dom-fixed.png` | Same URL against `:8002` -> the payload is shown as literal welcome text ("Welcome, &lt;img...&gt;!"), no alert. |
| `05-csp-vuln.png` | Browser DevTools Console on `:8001` (no CSP errors shown, because there is no CSP) next to Network tab showing no `Content-Security-Policy` response header. |
| `05-csp-fixed.png` | Same on `:8002`: if you manually inject an inline script via DevTools/a proxy, the Console shows a CSP violation and the script does not run; Network tab shows the `Content-Security-Policy` header. |
| `diff.png` | `diff vulnerable/app.py fixed/app.py` in a terminal. |

## Reproducing

```bash
cd Assigments/Assigment_4
bash exploits/run-demo.sh          # regenerates demo-output.txt
```
