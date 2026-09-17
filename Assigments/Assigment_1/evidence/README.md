# Evidence

`demo-output.txt` is the auto-generated transcript from `bash exploits/run-demo.sh`
(every exploit run against both the vulnerable :5001 and fixed :5002 builds).

## Screenshots to capture for the report

The grading rubric gives 2 marks for "quality of screenshots/evidence". Capture
these with Burp Suite (Proxy → HTTP history / Repeater) or OWASP ZAP and save
them here with the filenames the report references.

| File | What it should show |
| --- | --- |
| `01-authbypass-vuln.png` | Burp Repeater: `POST /login` with `username=' OR '1'='1' -- ` → response contains "Welcome back, admin (role: admin)". |
| `01-authbypass-fixed.png` | Same request to `:5002` → response "Login failed." |
| `02-union-vuln.png` | `GET /search?q=` with the UNION payload → response listing `admin:S3cr3t_admin_pw!`, `alice:…`, `bob:…`. |
| `02-union-fixed.png` | Same request to `:5002` → "0 result(s)". |
| `03-error-vuln.png` | `GET /search?q='` → response body shows `SQL error: unrecognized token` and the full `SELECT … WHERE name LIKE '%'%'`. |
| `03-error-fixed.png` | Same request to `:5002` → generic page, no error text. |
| `04-blind-vuln.png` | Two `GET /product?id=` requests side by side: one payload returning "Product #…" (TRUE), one returning "No such product." (FALSE); plus the terminal showing `exploits/04-boolean-blind.sh` recovering `S3cr3t_admin_pw!`. |
| `04-blind-fixed.png` | `GET /product?id=-1 OR …` to `:5002` → "Invalid product id." |
| `diff.png` | `diff vulnerable/app.py fixed/app.py` in a terminal. |

## Reproducing

```bash
cd Assigments/Assigment_1
bash exploits/run-demo.sh          # regenerates demo-output.txt
```
