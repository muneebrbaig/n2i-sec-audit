# Audit checklist

Load at the start of every audit. Each item has a stable ID. Reports, re-audits, and tickets all key on these IDs, so never renumber. New items take the next free number in their category.

Items marked **Core: yes** are the baseline every audit covers. **Core: no** items are extended checks; run them unless config lists them under `CHECK_SKIP`.

## How to judge an item

Give every item one status:

| Status | Meaning |
|---|---|
| `covered` | Evidence shows the control works. Cite `file:line` or the command and its result. |
| `partial` | The control exists but has a named gap. Describe the gap. |
| `gap` | The control is missing or broken. |
| `n/a` | The surface does not exist (for example, no file upload endpoint). State how you confirmed that. |
| `not-verified` | You could not check it (needs runtime, a deployed environment, or access you lack). Say what is needed. |

Rules:
- No status without evidence. "Looks fine" is `not-verified`.
- `n/a` claims need a negative search you actually ran. The skeptic agent tries to disprove them.
- A scan hit is a lead. Read the code before you call it a gap.
- Rate severity as likelihood times impact for this product. See `references/report-template.md` for the rubric.
- Never copy a secret value into any output. Cite the location and the kind of secret.

Mapping codes: OWASP Top 10 2021 (A01–A10), OWASP API Security Top 10 2023 (API1–API10), and CWE.

---

## A. Injection and input handling

### A1 SQL injection
- **Core:** yes
- **Look for:** every place SQL is built or executed. Raw-query APIs, string concatenation or interpolation into SQL, dynamic table or column names, ORM escape hatches, stored-procedure calls built from strings.
- **Pass when:** all request-path queries use parameters or an ORM's parameterized form. Dynamic identifiers come from an allowlist, never from input.
- **Severity if failing:** High to Critical
- **Maps to:** OWASP A03:2021, API8:2023 · CWE-89
- **Scan:** `scan.py` A1 lists raw-SQL candidates. It is a heuristic and cannot prove absence.

### A2 Cross-site scripting (XSS)
- **Core:** yes
- **Look for:** raw HTML sinks (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`, template `safe`/`mark_safe`, sanitizer bypass calls), user content in rich-text editors, HTML export features, and whether a Content-Security-Policy backs the escaping.
- **Pass when:** output is escaped by default, every raw sink is justified and sanitized, and a CSP limits what injected script could do.
- **Severity if failing:** Medium to High (High when tokens are script-readable, see C3)
- **Maps to:** OWASP A03:2021 · CWE-79
- **Scan:** header check (D6) covers CSP presence on a running target.

### A3 Cross-site request forgery (CSRF)
- **Core:** yes
- **Look for:** how the session is carried. Cookie-based sessions need CSRF tokens or `SameSite` plus origin checks on every state-changing route. Header-based bearer tokens are not CSRF-prone, but moving them to cookies later makes this item live.
- **Pass when:** either no ambient credentials are sent by the browser, or every state-changing request is protected.
- **Severity if failing:** Medium to High
- **Maps to:** OWASP A01:2021 · CWE-352
- **Scan:** cookie flag check (B7) on a running target.

### A4 File upload validation
- **Core:** yes
- **Look for:** multipart or file-accepting endpoints, size limits, type checks by content (not extension or client MIME), storage location (outside the web root), generated file names, archive extraction, image processing libraries.
- **Pass when:** no upload surface exists (`n/a`), or type, size, content, name, and storage are all controlled server-side.
- **Severity if failing:** High to Critical
- **Maps to:** OWASP A04:2021 · CWE-434

### A5 Server-side request forgery (SSRF)
- **Core:** yes
- **Look for:** server code that fetches a URL influenced by a user, tenant, or stored setting: webhooks you send, URL previews, import-from-URL, SMS/email gateway URLs, PDF or image renderers.
- **Pass when:** no user-influenced outbound URLs exist, or they pass an allowlist and a private-address block (loopback, link-local, cloud metadata ranges) and redirects are re-validated.
- **Severity if failing:** Medium to Critical (cloud metadata reachability raises it)
- **Maps to:** OWASP A10:2021, API7:2023 · CWE-918

### A6 Unsafe deserialization and mass assignment
- **Core:** no
- **Look for:** binary or polymorphic deserializers on untrusted input, `pickle`/`yaml.load`/`BinaryFormatter`-style APIs, request bodies bound straight onto persistence models (role, tenant id, price, `isAdmin` fields).
- **Pass when:** untrusted input only reaches safe parsers and input DTOs list the writable fields and nothing else.
- **Severity if failing:** High to Critical
- **Maps to:** OWASP A08:2021, API3:2023 · CWE-502, CWE-915

---

## B. Authentication and access control

### B1 Broken object-level authorization (BOLA/IDOR)
- **Core:** yes
- **Look for:** every endpoint that takes an object id. Does the code verify the caller may touch that specific object (owner, tenant, role)? In multi-tenant systems, does every query carry the tenant filter, and is it enforced centrally or by developer discipline? Are ids guessable (sequential integers)?
- **Pass when:** object access is checked on every route, ideally by a central mechanism (global query filter, policy handler), and an automated cross-tenant test proves it.
- **Severity if failing:** High to Critical
- **Maps to:** OWASP A01:2021, API1:2023 · CWE-639, CWE-285
- **Note:** the absence of a cross-tenant test suite is itself a `partial`, even when every route looks correct today.

### B2 Rate limiting and abuse controls
- **Core:** yes
- **Look for:** limits on login, registration, password reset, OTP, and expensive or enumerable endpoints; a global per-user or per-IP limit; what the limiter keys on (a client-controlled header is a weak key); behavior behind a proxy (all clients sharing one IP).
- **Pass when:** auth-sensitive routes have tight limits and the rest of the API has a general limit keyed on something the client cannot choose.
- **Severity if failing:** Medium to High
- **Maps to:** OWASP A04:2021, API4:2023 · CWE-770, CWE-307

### B3 Password storage and credential policy
- **Core:** yes
- **Look for:** the hashing algorithm and work factor (Argon2id, bcrypt, scrypt, PBKDF2 with a current iteration count), salting, minimum length and complexity or breached-password checks, lockout or throttling, reset-flow token strength and expiry.
- **Pass when:** a slow salted hash is used, policy matches current guidance, and repeated failures are throttled.
- **Severity if failing:** High to Critical
- **Maps to:** OWASP A02:2021, A07:2021 · CWE-916, CWE-521

### B4 Multi-factor authentication
- **Core:** yes
- **Look for:** whether a second factor exists (TOTP, WebAuthn, push), who can or must use it, recovery codes, and reset procedures. A user-model flag with no enrollment or login flow is a gap.
- **Pass when:** privileged accounts require MFA and others can opt in, with a safe recovery path.
- **Severity if failing:** Medium to High (High when admin accounts can act across tenants)
- **Maps to:** OWASP A07:2021 · CWE-308

### B5 Server-side permission enforcement and default-deny
- **Core:** yes
- **Look for:** where authorization decisions live. Per-route attributes or decorators, a fallback or default policy, roles re-read from the datastore versus trusted from a long-lived token, UI-only hiding of actions, routes that forgot a check.
- **Pass when:** the server enforces every decision, new routes are denied by default, and a test enumerates routes with their policies.
- **Severity if failing:** High to Critical
- **Maps to:** OWASP A01:2021, API5:2023 · CWE-862, CWE-863

### B6 Database-level isolation (row-level security)
- **Core:** yes
- **Look for:** database policies that enforce tenant or owner boundaries independent of application code, the database role the app connects with (owner roles bypass policies), and how the tenant context reaches the connection (including pooling).
- **Pass when:** RLS or an equivalent backstop exists for tenant data, or the report states why application-level isolation alone is accepted.
- **Severity if failing:** Medium (defense in depth behind B1)
- **Maps to:** OWASP A01:2021 · CWE-284

### B7 Session and token lifetime, revocation, and cookie flags
- **Core:** no
- **Look for:** access-token lifetime, refresh-token rotation and revocation on logout and password change, token transport (header, cookie, URL query string), cookie flags (`HttpOnly`, `Secure`, `SameSite`).
- **Pass when:** lifetimes are short, refresh tokens rotate and can be revoked, tokens never travel in URLs, and cookies carry the right flags.
- **Severity if failing:** Medium to High
- **Maps to:** OWASP A07:2021 · CWE-613, CWE-1004, CWE-598
- **Scan:** `scan.py` B7 checks cookie flags on a running target.

---

## C. Secrets and tokens

### C1 Signing keys and JWT secrets
- **Core:** yes
- **Look for:** key source (environment, secret manager, committed file), length and randomness, algorithm pinning (reject `none` and unexpected algorithms), where validation happens (duplicate validators can drift), key rotation procedure.
- **Pass when:** keys are random, at least 256 bits, loaded from a secret store, algorithms are pinned, and rotation is documented.
- **Severity if failing:** High to Critical
- **Maps to:** OWASP A02:2021 · CWE-321, CWE-347

### C2 API secrets stay server-side
- **Core:** yes
- **Look for:** third-party keys in frontend source, built bundles, mobile app packages, runtime config files served to browsers, and public environment variables (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `environment.ts`).
- **Pass when:** browsers and apps receive only public identifiers. Secret-bearing calls go through the backend.
- **Severity if failing:** High to Critical
- **Maps to:** OWASP A02:2021, A05:2021 · CWE-798, CWE-540
- **Note:** scan the built output as well as the source. A clean source tree can still ship a key through a build step.

### C3 Tokens kept out of script-readable browser storage
- **Core:** yes
- **Look for:** access or refresh tokens written to `localStorage`, `sessionStorage`, or IndexedDB; whole user objects (which contain tokens) stored there; tokens placed in URLs (query strings land in logs and `Referer`).
- **Pass when:** access tokens live in memory and long-lived tokens in `HttpOnly` cookies or platform secure storage. If cookies are used, A3 is covered.
- **Severity if failing:** High (any XSS becomes account takeover)
- **Maps to:** OWASP A02:2021 · CWE-922, CWE-598
- **Scan:** `scan.py` C3 lists `setItem` candidates.

### C4 Default and shared credentials
- **Core:** yes
- **Look for:** seeded admin accounts, documented default passwords, one credential reused across environments, credentials in README or setup docs, vendor defaults on databases and dashboards.
- **Pass when:** every environment has unique, rotated secrets held in a secret manager, and no default account survives first run.
- **Severity if failing:** High to Critical (Critical when production is included)
- **Maps to:** OWASP A07:2021 · CWE-1392, CWE-798
- **Note:** check for the existence and git-ignore status of local credential files without reading their contents.

### C5 Secrets in the repository and its history
- **Core:** yes
- **Look for:** tracked `.env`/key/certificate files, secret-shaped strings in source, CI variables printed in logs, secrets that were committed once and later deleted (history).
- **Pass when:** no secret is tracked, local secret files are git-ignored, and a history scan is clean (or findings are rotated).
- **Severity if failing:** High to Critical
- **Maps to:** OWASP A02:2021, A05:2021 · CWE-798, CWE-312
- **Scan:** `scan.py` C5 uses gitleaks when installed (history included). Otherwise it uses a built-in pattern scan of the working tree and says history was not scanned.

---

## D. Configuration and hygiene

### D1 CORS
- **Core:** yes
- **Look for:** wildcard origins, reflected `Origin`, credentials allowed with broad origins, over-broad methods and headers, per-environment origin lists.
- **Pass when:** origins come from an explicit allowlist per environment and credentials are allowed only for those.
- **Severity if failing:** Medium to High
- **Maps to:** OWASP A05:2021, API8:2023 · CWE-942
- **Scan:** `scan.py` D1 flags wildcard patterns.

### D2 Webhook and callback verification
- **Core:** yes
- **Look for:** inbound endpoints called by third parties (payments, messaging, CI, scheduled-job triggers). Signature or shared-secret verification, constant-time comparison, timestamp and replay protection, idempotency.
- **Pass when:** no inbound webhooks exist (`n/a`), or each verifies a signature or secret in constant time and rejects replays.
- **Severity if failing:** High
- **Maps to:** OWASP A08:2021, API10:2023 · CWE-345, CWE-294

### D3 Exposed source maps and debug surfaces
- **Core:** yes
- **Look for:** `.map` files in production output, debug or developer pages enabled in production (Swagger UI, GraphQL playground, profilers, `/debug`, framework debug flags), directory listing, exposed `.git`.
- **Pass when:** production builds emit no public source maps and debug surfaces are off or authenticated.
- **Severity if failing:** Low to Medium
- **Maps to:** OWASP A05:2021 · CWE-540, CWE-489
- **Scan:** `scan.py` D3 counts `.map` files in build output directories.

### D4 Sensitive data in logs
- **Core:** yes
- **Look for:** logging of passwords, tokens, OTPs, API keys, full request bodies, personal data, message contents; secrets in URLs that access logs capture; redaction rules and tests; log retention and access.
- **Pass when:** secrets and personal data never reach logs, redaction is tested, and URLs carry no secrets.
- **Severity if failing:** Medium to High
- **Maps to:** OWASP A09:2021 · CWE-532
- **Note:** also check fallback or no-op modes (a "log instead of send" SMS or email mode can log the OTP).

### D5 Vulnerable dependencies
- **Core:** yes
- **Look for:** known-vulnerable direct and transitive packages for every ecosystem in the repo, lockfile presence, unmaintained packages, update cadence, a CI audit step.
- **Pass when:** no critical or high advisories in production dependencies, or each has a dated, owned exception.
- **Severity if failing:** by advisory: Critical and High advisories on reachable code are High
- **Maps to:** OWASP A06:2021 · CWE-1395
- **Scan:** `scan.py` D5 runs `npm audit`, `dotnet list package --vulnerable`, and `pip-audit` when present. These need network access; use `--offline` to skip.

### D6 Security headers, CSP, and transport security
- **Core:** no
- **Look for:** `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, frame protection, `Referrer-Policy`; HTTPS redirection; TLS configuration at the edge.
- **Pass when:** the headers are present and meaningful, and plaintext HTTP redirects or is refused.
- **Severity if failing:** Medium
- **Maps to:** OWASP A05:2021 · CWE-693, CWE-319
- **Scan:** `scan.py --url` checks response headers on a local or owned target.

### D7 Error and information leakage
- **Core:** no
- **Look for:** stack traces or exception messages in responses, verbose framework error pages, server and framework version banners, user-enumeration differences in login and reset responses.
- **Pass when:** clients see generic errors with a correlation id, and banners and enumeration signals are removed.
- **Severity if failing:** Low to Medium
- **Maps to:** OWASP A05:2021 · CWE-209, CWE-204

### D8 Audit logging and monitoring
- **Core:** no
- **Look for:** logs of authentication events, privilege changes, cross-tenant access, and admin actions; alerts on repeated failures; log integrity and retention; whether anyone would notice an incident.
- **Pass when:** security-relevant events are recorded with who, what, when, and from where, and someone is alerted.
- **Severity if failing:** Medium
- **Maps to:** OWASP A09:2021 · CWE-778

### D9 Build, CI, and supply chain
- **Core:** no
- **Look for:** secrets exposed to untrusted pipeline runs, unpinned CI actions or images, container images running as root, unreviewed install scripts, no dependency or secret scanning in CI, release artifacts without integrity checks.
- **Pass when:** pipelines limit each secret to the jobs that need it, pin third-party components, and run dependency and secret scans.
- **Severity if failing:** Medium to High
- **Maps to:** OWASP A08:2021, A06:2021 · CWE-829
