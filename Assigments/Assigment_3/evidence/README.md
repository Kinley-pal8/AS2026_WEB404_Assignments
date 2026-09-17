# Evidence

`demo-output.txt` is the auto-generated transcript from `bash exploits/run-demo.sh`
(every check run against both the vulnerable :7001 and fixed :7002 builds).

## Screenshots to capture for the report

The grading rubric gives 2 marks for "quality of screenshots/evidence". Capture
these with Burp Suite (Proxy -> HTTP history / Repeater) and save them here
with the filenames the report references.

| File | What it should show |
| --- | --- |
| `01-internal-vuln.png` | Burp Repeater: `POST /preview` with `url=http://127.0.0.1:7099/internal/admin` against `:7001` -> response contains `db_password`. |
| `01-internal-fixed.png` | Same request against `:7002` (with a Bearer token) -> `{"error": "... resolves to non-public address 127.0.0.1"}`. |
| `02-metadata-vuln.png` | `url=http://127.0.0.1:7099/latest/meta-data/iam/security-credentials/webapp-role` against `:7001` -> `AccessKeyId`/`SecretAccessKey` in the response. |
| `02-metadata-fixed.png` | Same request against `:7002` -> blocked, same reason as above. |
| `03-redirect-vuln.png` | `url=http://127.0.0.2:7050/bounce` against `:7001` -> `final_url` in the response shows it landed on `127.0.0.1:7099/internal/admin`. |
| `03-redirect-fixed.png` | Same request against `:7002` -> blocked. |
| `04-file-vuln.png` | `url=file:///etc/hostname` against `:7001` -> the file's contents in `snippet`. |
| `04-file-fixed.png` | Same request against `:7002` -> `{"error": "scheme 'file' is not allowed ..."}`. |
| `05-auth-vuln.png` | `POST /preview` against `:7001` with **no** `Authorization` header -> still succeeds. |
| `05-auth-fixed.png` | Same request against `:7002` -> `{"error": "login required"}`. |
| `diff.png` | `diff vulnerable/app.py fixed/app.py` in a terminal. |

## Reproducing

```bash
cd Assigments/Assigment_3
bash exploits/run-demo.sh          # regenerates demo-output.txt
```
