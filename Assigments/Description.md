# WEB404 Secure Coding Practices - Assignment Topics Reference

**Purpose of this document:** This file describes the selected assignment topics, their technical scope, and the official grading criteria from the module descriptor. Use this as a reference/context document when working with an AI assistant on any of these assignments - paste the relevant topic section (plus the "Grading Criteria" section) into the chat so the AI understands exactly what's expected before helping you build, write, or review the work.

**Module:** WEB404 Secure Coding Practices
**Total topics selected:** 5 (4 will be graded as formal assignments; confirm with your tutor which 4 count, or which one is treated separately)

---

## How to use this file with an AI

When starting a session on one topic, give the AI:
1. The specific topic's **Description**, **Technical Scope**, and **Deliverables** sections below.
2. The **Grading Criteria** section (shared across all topics).
3. A note on which stage you're at (e.g. "I'm building the vulnerable version" or "I need help writing the remediation section of my report").

This keeps the AI's help scoped to what will actually be assessed, rather than general tutorial content.

---

## Topic 1: SQL Injection - Build & Defend

### Description
Set up a deliberately vulnerable web application with a database-backed feature (e.g. login form or search function), demonstrate exploitation using at least two SQL injection techniques (e.g. UNION-based and blind/boolean-based), then remediate the vulnerability using parameterized queries or an ORM, and document the before/after behavior.

### Technical Scope
- Vulnerable input point (form field, URL parameter, or API endpoint) connected to a database
- Exploitation: UNION-based SQLi, blind/boolean-based SQLi, or error-based SQLi
- Tools: Burp Suite or OWASP ZAP for testing/interception
- Remediation: parameterized queries, prepared statements, or ORM usage
- Optional hardening: input validation, least-privilege DB accounts, WAF rule

### Deliverables
- Working vulnerable version (code + screenshots of successful exploitation)
- Working fixed version (code + proof the exploit no longer works)
- Short report explaining the vulnerability mechanism and why the fix works

### Maps to Learning Outcomes
LO2 (attack mechanisms), LO4 (server-side vulnerabilities), LO5 (assess effectiveness of fixes), LO6 (secure development)

---

## Topic 2: JWT Authentication Attacks

### Description
Build a JWT-based authentication system, demonstrate at least two JWT-specific attacks (e.g. `alg:none` bypass, signature stripping, weak-secret brute force, or algorithm confusion), then implement secure JWT handling with proper signing, validation, and expiry.

### Technical Scope
- JWT-based login/session system (any backend stack)
- Attacks: `alg:none` bypass, HS256/RS256 algorithm confusion, weak secret brute-forcing, token expiry/replay issues
- Tools: Burp Suite, jwt_tool, or manual token crafting
- Remediation: strong secret/key management, algorithm whitelisting, short expiry + refresh tokens, signature verification enforcement

### Deliverables
- Working vulnerable JWT implementation (code + proof of successful attack)
- Secured version (code + proof the attack is blocked)
- Report explaining JWT structure, the specific weakness exploited, and the fix

### Maps to Learning Outcomes
LO2, LO7 (advanced attacks: JWT), LO8 (secure API architecture)

---

## Topic 3: Server-Side Request Forgery (SSRF) + Access Control

### Description
Build a feature that fetches a resource based on user-supplied input (e.g. a URL preview or image-import feature), exploit it to reach internal/restricted resources, then remediate with URL whitelisting and proper authorization checks.

### Technical Scope
- Feature that makes server-side requests based on user input (URL fetcher, webhook tester, PDF/image importer, etc.)
- Exploitation: reaching internal network resources, cloud metadata endpoints, or bypassing IP/domain filters
- Remediation: strict allow-listing of destinations, blocking internal IP ranges, disabling redirects, proper authorization on the fetching feature

### Deliverables
- Vulnerable version (code + proof of reaching a restricted/internal resource)
- Fixed version (code + proof the bypass no longer works)
- Report covering SSRF mechanics and the specific mitigation applied

### Maps to Learning Outcomes
LO2, LO5, LO6 (this topic pulls from syllabus section 3.4-3.6, which has no dedicated practical listed - good for covering otherwise-unassessed material)

---

## Topic 4: Cross-Site Scripting (XSS) - Reflected / Stored / DOM-based + CSP

### Description
Build a web feature vulnerable to all three XSS types (reflected, stored, and DOM-based), demonstrate exploitation of each, then remediate using output encoding and a Content Security Policy (CSP).

### Technical Scope
- Reflected XSS: unsanitized input echoed back in a response (e.g. search results page)
- Stored XSS: unsanitized input saved and rendered later (e.g. comment/profile field)
- DOM-based XSS: client-side JavaScript writing untrusted data into the DOM (e.g. via `innerHTML`)
- Remediation: context-aware output encoding, input sanitization, CSP headers, secure cookie attributes (`HttpOnly`, `Secure`, `SameSite`)

### Deliverables
- Three working vulnerable examples (one per XSS type) with proof-of-concept payloads
- Fixed versions with CSP configuration and encoding applied
- Report covering each XSS type's mechanism and the specific defense used

### Maps to Learning Outcomes
LO2, LO5, LO6

---

## Topic 5: Server-Side Template Injection (SSTI)

### Description
Choose a server-side template engine (e.g. Jinja2, Twig, FreeMarker), build a feature that renders user input through the template engine, exploit it to achieve remote code execution (RCE) or sensitive data disclosure, then remediate using sandboxing and proper input handling.

### Technical Scope
- Template engine of choice rendering user-controllable input
- Exploitation: payload injection to execute template-engine expressions, escalate to RCE where possible
- Remediation: logic-less templates, sandboxed execution environments, strict separation of user input from template logic, auto-escaping

### Deliverables
- Vulnerable version (code + proof of successful template injection/RCE)
- Fixed version (code + proof the payload is neutralized)
- Report explaining the template engine's rendering process and why the fix closes the gap

### Maps to Learning Outcomes
LO2, LO7 (advanced web attacks - explicitly listed in syllabus 5.3)

---

## Grading Criteria (applies to each assignment, out of 10 marks)

| Criterion | Marks | What it's assessing |
| --- | --- | --- |
| Technical Accuracy & Methodology | 3.25 | Correctness of the exploit, correctness of the fix, sound testing process |
| Application of Concepts | 3.25 | Depth of understanding shown - not just "it worked" but *why* it worked and *why* the fix works |
| Presentation and Elaboration | 2 | Clarity of the report/writeup, quality of screenshots/evidence, logical structure |
| Timely Submission and Language | 1.5 | Submitted on time, clear written English, proper formatting |

**Presentation component (separate, 10% of module total, 10-minute presentation on one assignment):**

| Criterion | Weight |
| --- | --- |
| Delivery | 2 |
| Content | 3 |
| Answer to Questions | 3 |
| Presentation Aids | 2 |

---

## Suggested workflow per assignment

1. **Research phase** - confirm the vulnerability mechanism and current best-practice fix (cite OWASP where possible)
2. **Build phase** - vulnerable version first, test it works, screenshot/log proof
3. **Exploit phase** - document the attack step-by-step with tool output (Burp/ZAP requests, payloads used)
4. **Fix phase** - implement remediation, re-test to prove the exploit is blocked
5. **Report phase** - write up mechanism, impact, and fix, mapped to the grading criteria above
6. **Review phase** - check submission against "Application of Concepts" and "Technical Accuracy" - this is where most marks are lost if the *why* isn't explained

---
