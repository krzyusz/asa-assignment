# Security Findings — VulnTracker

Task 2b. Findings from the automated scans (Step 4) plus manual code review of
`app/` and `notify/`. Raw scan output is in [`reports/`](../reports/).

**Severities are my assessment**, weighted by business context, not the raw tool
rating. Guiding weights for this system:

- It stores customers' **unremediated vulnerabilities** — that data is a ready-made
  attack plan, so confidentiality of scan records is unusually high-value.
- Auth bypass > bulk data theft > SSRF/DoS > information disclosure.
- Unauthenticated-reachable is worse than authenticated-only.

Scope tag: **[starter]** = pre-existing code, **[new]** = code added in this
assignment (Task 1 share links, Docker, Helm).

---

## Headline numbers (raw, pre-triage)

| Scan | Tool(s) | Raw result |
| ---- | ------- | ---------- |
| SAST | Semgrep | 7 findings (2 ERROR, 4 WARNING, 1 INFO); 1 is a false positive |
| SCA | Trivy `fs` | 1 CRITICAL, ~26 HIGH across `requirements.txt` + `notify/package-lock.json` |
| Container image | Trivy `image` | 6 CRITICAL, 50 HIGH — 5 criticals are unfixable Debian base CVEs; secret scan clean |
| IaC | Trivy `config`, Checkov, Prowler `iac` | Trivy/Prowler 3 (identical — Prowler wraps Trivy); Checkov 7; both Dockerfiles 0 |

The raw counts are dominated by non-actionable noise (unfixable OS CVEs,
transitive dependency DoS, namespace-in-`helm template` artifacts). The triage
below is what actually matters.

---

## Prioritised findings

### P0 — exploitable now, catastrophic impact

| # | Finding | Detected by | Severity | Location | Scope | Business impact |
|---|---------|-------------|----------|----------|-------|-----------------|
| 1 | **SQL injection in scan search.** `q` is interpolated into raw SQL with an f-string (`WHERE title LIKE '%{query}%'`). | Semgrep (SAST, flagged `text()` as low) + manual | **Critical** | `app/database.py:20-29`, reached from `GET /scans/search` | starter | Any registered user can read or modify the entire database — every customer's scan records **and the `users` table** (usernames, emails, bcrypt hashes). One low-privilege account = full data breach. SQLite limits stacked writes but boolean/`UNION` exfiltration is trivial. |
| 2 | **JWT `none` algorithm accepted.** `jwt.decode(..., algorithms=[ALGORITHM, "none"])` explicitly allows unsigned tokens. | Semgrep (`jwt-python-none-alg`, ERROR) | **Critical** | `app/auth.py:38` | starter | Anyone can craft `{"alg":"none","sub":"<any user>"}` and be authenticated as that user — no secret needed. Complete authentication bypass and horizontal privilege escalation over every endpoint. |
| 3 | **Hardcoded fallback secrets in source & git history.** `SECRET_KEY`, `DB_PASSWORD`, `ADMIN_API_KEY` (`config.py`); `SERVICE_KEY` (`notify/src/config.js`). | Semgrep (`p/secrets`) + manual + Trivy secret scan | **Critical** | `app/config.py:11,17,20`; `notify/src/config.js:6` | starter (values); parametrisation is [new] | If HS256 is used correctly, knowing `SECRET_KEY` is equivalent to finding #2 — forge any token. The value is committed and in history, so rotation requires invalidating all issued tokens. `DB_PASSWORD`/`ADMIN_API_KEY` are currently unused but would leak real credentials the moment they are wired up. |

### P1 — high impact, straightforward to exploit

| # | Finding | Detected by | Severity | Location | Scope | Business impact |
|---|---------|-------------|----------|----------|-------|-----------------|
| 4 | **IDOR on `GET /scans/{id}`.** No `owner_id` filter, unlike `list` / `update` / `delete`. | Manual (Semgrep does not model authz) | **High** | `app/main.py:268-276` | starter | Any authenticated user reads any scan by incrementing the id — the whole vulnerability database, one record at a time. Same confidentiality loss as #1 without needing injection skills. |
| 5 | **Unauthenticated internal notification service.** `POST /webhooks`, `GET /webhooks`, `POST /notify` have no auth ("assumed internal"). | Manual | **High** | `notify/src/index.js:14,36,53` | starter | Any actor with network reach registers webhooks or replays events. Combined with #6 this is a full SSRF primitive. "Assumed internal" is not enforced anywhere — no `NetworkPolicy`, no mTLS, no shared secret check. |
| 6 | **SSRF via webhook dispatch.** `axios.post(webhook.url, ...)` where `webhook.url` is fully attacker-controlled; no scheme/host allow-list, no block on private ranges or link-local. The internal `X-Service-Key` header is sent to that URL. | Manual + Semgrep (`express-data-exfiltration`, related) + SCA (`axios` CVE-2025-27152) | **High** | `notify/src/dispatcher.js:7-13` | starter | Register `http://169.254.169.254/latest/meta-data/...` → the service fetches cloud instance credentials and (via retries/errors) can leak them. Also internal port scanning and hitting internal-only admin endpoints. `axios 0.21.1` independently has an SSRF/credential-leak CVE that makes even a URL allow-list bypassable. |
| 7 | **Verbose error responses leak internals.** FastAPI global handler returns `str(exc)`, exception type and full `traceback` to the client; notify returns `err.message` + `err.stack`. | Manual | **High** | `app/main.py:52-63`; `notify/src/index.js:77-80` | starter | Stack traces expose file paths, library versions, SQL fragments and query structure — a roadmap for exploiting #1 and others. Also a compliance issue (information disclosure). |
| 8 | **Plaintext passwords written to logs on every login.** Both the info log and the failed-login warning include `payload.password`. | Semgrep (`python-logger-credential-disclosure`, WARNING) | **High** | `app/main.py:200,204` | starter | Every login attempt copies a live credential into stdout → the log pipeline (Loki/CloudWatch/ELK), where it is broadly readable and long-retained. A log export or an over-permissioned analyst = credential compromise at scale. |
| 9 | **`python-jose` 3.3.0 — CVE-2024-33663 (algorithm confusion).** Plus its `ecdsa` dependency (Minerva timing attack, no fix). | Trivy SCA + Trivy container | **High** (Critical CVSS, High here — HS256 in use limits the confusion vector, but see #2/#3) | `requirements.txt` | starter | Algorithm-confusion attacks on JWT verification — the same class of bug as #2, from the library side. The app's JWT handling is already the weakest area, so this compounds directly. |

### P2 — real issues, lower urgency or higher effort

| # | Finding | Detected by | Severity | Location | Scope | Business impact |
|---|---------|-------------|----------|----------|-------|-----------------|
| 10 | **Permissive CORS reflection.** Middleware echoes any `Origin`, sets `Allow-Credentials: true` and `Allow-Headers: *`. | Manual | **Medium** | `app/main.py:40-49` | starter | Any website can make credentialed cross-origin calls. Impact is bounded because auth is a `Bearer` header (not an automatically-sent cookie), but it removes a defence-in-depth layer and is dangerous if a browser client ever stores the token somewhere script-reachable. |
| 11 | **Outdated crypto / parsing libraries.** `cryptography 38.0.1` (multiple HIGH incl. bundled OpenSSL), `python-multipart 0.0.6` (ReDoS + DoS), `starlette`/`fastapi` transitive DoS. | Trivy SCA + container | **Medium** | `requirements.txt` | starter | Mostly DoS and theoretical crypto weaknesses rather than direct compromise, but `cryptography` underpins TLS and token signing — it should never be years behind. Low exploitation effort for the DoS ones. |
| 12 | **Vulnerable Express stack in notify.** `axios 0.21.1`, `path-to-regexp 0.1.7`, `body-parser 1.20.1` — ReDoS / prototype-pollution / DoS. | Trivy SCA + container | **Medium** | `notify/package-lock.json` | starter | A single crafted request can pin CPU and take the notification service down; prototype-pollution chains can escalate. `axios` also feeds finding #6. |
| 13 | **Container base-image CVEs.** 5 CRITICAL + ~29 HIGH in `python:3.11-slim-bookworm` (`libsqlite3`, `perl-base`, `zlib1g`, …). | Trivy container | **Medium** | `Dockerfile` base image | [new] (our image) / upstream | All are `will_not_fix` / `fix_deferred` in Debian — `apt upgrade` changes nothing. Real remediation is a smaller base (distroless / Chainguard / Alpine). Live risk is limited: non-root, read-only rootfs, dropped caps, and most flagged packages (perl) are never executed at runtime. |
| 14 | **No rate limiting on authentication or search.** | Manual | **Medium** | `app/main.py` login, search | starter | Unlimited password guessing against `/auth/login`; unlimited expensive `LIKE '%...%'` scans. The share-link password path *is* rate-limited (per-link lockout added in Task 1), but nothing else is. Needs a reverse proxy / API gateway or middleware. |
| 15 | **Weak password policy.** `register` accepts any non-empty password. | Manual | **Low** | `app/main.py` register | starter | Users pick `pw`; combined with #14 (no lockout) online guessing is easy. |
| 16 | **IaC: secrets delivered as env vars, image not digest-pinned by default.** | Checkov (`CKV_K8S_35`, `CKV_K8S_43`) | **Low** | `helm/vulntracker-api` | [new] | Env-var secrets are visible in `/proc/<pid>/environ` and crash dumps; a mutable tag allows drift/rollback ambiguity. The chart already *supports* `image.digest`; making it mandatory and switching to file-mounted secrets is a small hardening step. |
| 17 | **Share-link response distinguishes "valid but password-protected" (401) from "unknown" (404).** | Manual (review of own Task 1 code) | **Low** | `app/main.py` `GET /share/{token}` | [new] | A technical oracle: an attacker who guesses a token can tell it is real before knowing the password. Moot against 256-bit tokens, but the endpoint should return a uniform response and be rate-limited. This is the fix that will land in Task-1 code for Task 3. |

### False positives / non-issues (recorded so they are not re-raised)

| Finding | Source | Why it is not a finding |
|---------|--------|-------------------------|
| "Hardcoded secret being logged" at `main.py:367` | Semgrep `python-logger-credential-disclosure` | The log message for share-link creation merely contains the word "password" in a human string; no secret value is logged. |
| "ConfigMap with secrets" (`KSV-0109`, HIGH) | Trivy / Prowler IaC | The ConfigMap holds only non-secret config (`PUBLIC_BASE_URL`, `NOTIFY_SERVICE_URL`, prototype SQLite `DATABASE_URL`). Would become real if `DATABASE_URL` carried Postgres credentials — those are already routed through `secrets.items` instead. |
| "Workloads in the default namespace" (`KSV-0110` / `CKV_K8S_21`) | Trivy / Checkov IaC | Artifact of `helm template` without `-n`; the chart never hardcodes a namespace and `helm install` sets it. |
| "Restrict images to trusted registries" (`KSV-0125`) | Trivy IaC | `ghcr.io/<org>` is our own registry; the check has no configured allow-list. Informational. |
| `imagePullPolicy` should be `Always` (`CKV_K8S_15`) | Checkov IaC | With digest-pinned images, `IfNotPresent` is correct and avoids needless registry load. |
| Missing CSRF middleware in notify (`express-check-csurf...`) | Semgrep | The service is a token-less JSON API with no cookies/sessions; CSRF does not apply. The real problem is #5 (no auth at all). |

---

## Triage — fix order and why

| Pri | Finding(s) | Rationale |
| --- | ---------- | --------- |
| **P0** | #1 SQLi | single worst bug — full DB read/write from any account |
| **P0** | #2 JWT `none` + #3 `SECRET_KEY` | auth bypass; cheap to exploit, total impact; #9 compounds it |
| **P1** | #4 IDOR | same data-breach impact as #1, no skill needed |
| **P1** | #7 error/stack disclosure | multiplies exploitability of everything else |
| **P1** | #8 password logging | turns the log store into a credential store |
| **P1** | #5 + #6 notify no-auth + SSRF | unauthenticated path to cloud-metadata credential theft |
| **P2** | #11–#13 dependency + base-image CVEs | mostly DoS / theoretical; higher effort, lower per-item impact |
| **P2** | #10 CORS, #14 rate limiting | defence-in-depth; #14 partly needs infra |
| **P3** | #15–#17 | low real-world impact given other controls |

### What I am planning to fix

At least: **#1 (SQLi)**, **#2 + #3 (JWT `none` / `SECRET_KEY`)**, **#4 (IDOR)**, and
**#17** (the hardening in Task-1 share-link code). Rationale: these are the P0/P1
items that are (a) pure code changes, (b) fully within this repo's control, and
(c) remove the "any user → full breach" and "no user → full breach" paths.

Everything else is deferred for now; the residual-risk / effort / compensating-control
write-up will follow in `docs/remediation-plan.md`.

---

## Positive findings

- The container image contains **no secrets** (Trivy secret scan clean) and both
  Dockerfiles pass all Trivy misconfig checks — the Step 1 hardening holds.
- The Helm chart passes the large majority of Trivy (403) and Checkov (86)
  policy checks; the residual items are low severity.
- The Task 1 share-link feature uses a 256-bit token stored only as a hash,
  bcrypt for the optional password, server-side expiry, owner-only creation, and
  a per-link lockout — the only issue found in it is the low-severity #17.
