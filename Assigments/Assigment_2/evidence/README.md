# Evidence

`demo-output.txt` is the auto-generated transcript from `bash exploits/run-demo.sh`
(every exploit run against both the vulnerable :6001 and fixed :6002 builds).

## Screenshots to capture for the report

The grading rubric gives 2 marks for "quality of screenshots/evidence". Capture
these with Burp Suite (Proxy -> HTTP history / Repeater) or `jwt_tool` and save
them here with the filenames the report references.

| File | What it should show |
| --- | --- |
| `01-none-vuln.png` | Burp Repeater: `GET /account` with `Authorization: Bearer <forged alg:none token>` -> response contains `admin_secret`. |
| `01-none-fixed.png` | Same request to `:6002` -> `{"error": "unsupported alg"}`. |
| `02-bruteforce-vuln.png` | Terminal running `exploits/02-weak-secret-bruteforce.sh` -> `RECOVERED secret = 'secret123'`, then the forged admin token accepted. |
| `02-bruteforce-fixed.png` | Same script against `:6002` -> `secret not recovered from the wordlist`. |
| `03-replay-vuln.png` | `GET /account` with a token whose `exp` is in the past, against `:6001` -> `sub`/`role` returned (accepted). |
| `03-replay-fixed.png` | Same request against `:6002` -> `{"error": "expired"}`. |
| `jwt-io-decode.png` | A captured token pasted into jwt.io (or `jwt_forge.py decode`) showing the header/payload in plain text, to illustrate that a JWT is signed, not encrypted. |
| `diff.png` | `diff vulnerable/app.py fixed/app.py` in a terminal. |

## Reproducing

```bash
cd Assigments/Assigment_2
bash exploits/run-demo.sh          # regenerates demo-output.txt
```
