# Security Findings - VulnTracker

Task 2b. Findings from the automated scans (Step 4) plus manual code review of
`app/` and `notify/`. Raw scan output is in [`reports/`](../reports/).

**Severities are my assessment**, weighted by business context, not the raw tool
rating. Guiding weights for this system:

- It stores customers' **unremediated vulnerabilities** - that data is a ready-made
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
| Container image | Trivy `image` | 6 CRITICAL, 50 HIGH - 5 criticals are unfixable Debian base CVEs; secret scan clean |
| IaC | Trivy `config`, Checkov, Prowler `iac` | Trivy/Prowler 3 (identical - Prowler wraps Trivy); Checkov 7; both Dockerfiles 0 |

The raw counts are dominated by non-actionable noise (unfixable OS CVEs,
transitive dependency DoS, namespace-in-`helm template` artifacts). The triage
below is what actually matters.

---

## Prioritised findings

### P0 - exploitable now, catastrophic impact

| # | Finding | Detected by | Severity | Location | Scope | Business impact |
|---|---------|-------------|----------|----------|-------|-----------------|
| 1 | **SQL injection in scan search.** `q` is interpolated into raw SQL with an f-string (`WHERE title LIKE '%{query}%'`). | Semgrep (SAST, flagged `text()` as low) + manual | **Critical** | `app/database.py:20-29`, reached from `GET /scans/search` | starter | Any registered user can read or modify the entire database - every customer's scan records **and the `users` table** (usernames, emails, bcrypt hashes). One low-privilege account = full data breach. SQLite limits stacked writes but boolean/`UNION` exfiltration is trivial. |
| 2 | **JWT `none` algorithm accepted.** `jwt.decode(..., algorithms=[ALGORITHM, "none"])` explicitly allows unsigned tokens. | Semgrep (`jwt-python-none-alg`, ERROR) | **Critical** | `app/auth.py:38` | starter | Anyone can craft `{"alg":"none","sub":"<any user>"}` and be authenticated as that user - no secret needed. Complete authentication bypass and horizontal privilege escalation over every endpoint. |
| 3 | **Hardcoded fallback secrets in source & git history.** `SECRET_KEY`, `DB_PASSWORD`, `ADMIN_API_KEY` (`config.py`); `SERVICE_KEY` (`notify/src/config.js`). | Semgrep (`p/secrets`) + manual + Trivy secret scan | **Critical** | `app/config.py:11,17,20`; `notify/src/config.js:6` | starter (values); parametrisation is [new] | If HS256 is used correctly, knowing `SECRET_KEY` is equivalent to finding #2 - forge any token. The value is committed and in history, so rotation requires invalidating all issued tokens. `DB_PASSWORD`/`ADMIN_API_KEY` are currently unused but would leak real credentials the moment they are wired up. |

### P1 - high impact, straightforward to exploit

| # | Finding | Detected by | Severity | Location | Scope | Business impact |
|---|---------|-------------|----------|----------|-------|-----------------|
| 4 | **IDOR on `GET /scans/{id}`.** No `owner_id` filter, unlike `list` / `update` / `delete`. | Manual (Semgrep does not model authz) | **High** | `app/main.py:268-276` | starter | Any authenticated user reads any scan by incrementing the id - the whole vulnerability database, one record at a time. Same confidentiality loss as #1 without needing injection skills. |
| 5 | **Unauthenticated internal notification service.** `POST /webhooks`, `GET /webhooks`, `POST /notify` have no auth ("assumed internal"). | Manual | **High** | `notify/src/index.js:14,36,53` | starter | Any actor with network reach registers webhooks or replays events. Combined with #6 this is a full SSRF primitive. "Assumed internal" is not enforced anywhere - no `NetworkPolicy`, no mTLS, no shared secret check. |
| 6 | **SSRF via webhook dispatch.** `axios.post(webhook.url, ...)` where `webhook.url` is fully attacker-controlled; no scheme/host allow-list, no block on private ranges or link-local. The internal `X-Service-Key` header is sent to that URL. | Manual + Semgrep (`express-data-exfiltration`, related) + SCA (`axios` CVE-2025-27152) | **High** | `notify/src/dispatcher.js:7-13` | starter | Register `http://169.254.169.254/latest/meta-data/...` → the service fetches cloud instance credentials and (via retries/errors) can leak them. Also internal port scanning and hitting internal-only admin endpoints. `axios 0.21.1` independently has an SSRF/credential-leak CVE that makes even a URL allow-list bypassable. |
| 7 | **Verbose error responses leak internals.** FastAPI global handler returns `str(exc)`, exception type and full `traceback` to the client; notify returns `err.message` + `err.stack`. | Manual | **High** | `app/main.py:52-63`; `notify/src/index.js:77-80` | starter | Stack traces expose file paths, library versions, SQL fragments and query structure - a roadmap for exploiting #1 and others. Also a compliance issue (information disclosure). |
| 8 | **Plaintext passwords written to logs on every login.** Both the info log and the failed-login warning include `payload.password`. | Semgrep (`python-logger-credential-disclosure`, WARNING) | **High** | `app/main.py:200,204` | starter | Every login attempt copies a live credential into stdout → the log pipeline (Loki/CloudWatch/ELK), where it is broadly readable and long-retained. A log export or an over-permissioned analyst = credential compromise at scale. |
| 9 | **`python-jose` 3.3.0 - CVE-2024-33663 (algorithm confusion).** Plus its `ecdsa` dependency (Minerva timing attack, no fix). | Trivy SCA + Trivy container | **High** (Critical CVSS, High here - HS256 in use limits the confusion vector, but see #2/#3) | `requirements.txt` | starter | Algorithm-confusion attacks on JWT verification - the same class of bug as #2, from the library side. The app's JWT handling is already the weakest area, so this compounds directly. |

### P2 - real issues, lower urgency or higher effort

| # | Finding | Detected by | Severity | Location | Scope | Business impact |
|---|---------|-------------|----------|----------|-------|-----------------|
| 10 | **Permissive CORS reflection.** Middleware echoes any `Origin`, sets `Allow-Credentials: true` and `Allow-Headers: *`. | Manual | **Medium** | `app/main.py:40-49` | starter | Any website can make credentialed cross-origin calls. Impact is bounded because auth is a `Bearer` header (not an automatically-sent cookie), but it removes a defence-in-depth layer and is dangerous if a browser client ever stores the token somewhere script-reachable. |
| 11 | **Outdated crypto / parsing libraries.** `cryptography 38.0.1` (multiple HIGH incl. bundled OpenSSL), `python-multipart 0.0.6` (ReDoS + DoS), `starlette`/`fastapi` transitive DoS. | Trivy SCA + container | **Medium** | `requirements.txt` | starter | Mostly DoS and theoretical crypto weaknesses rather than direct compromise, but `cryptography` underpins TLS and token signing - it should never be years behind. Low exploitation effort for the DoS ones. |
| 12 | **Vulnerable Express stack in notify.** `axios 0.21.1`, `path-to-regexp 0.1.7`, `body-parser 1.20.1` - ReDoS / prototype-pollution / DoS. | Trivy SCA + container | **Medium** | `notify/package-lock.json` | starter | A single crafted request can pin CPU and take the notification service down; prototype-pollution chains can escalate. `axios` also feeds finding #6. |
| 13 | **Container base-image CVEs.** 5 CRITICAL + ~29 HIGH in `python:3.11-slim-bookworm` (`libsqlite3`, `perl-base`, `zlib1g`, …). | Trivy container | **Medium** | `Dockerfile` base image | [new] (our image) / upstream | All are `will_not_fix` / `fix_deferred` in Debian - `apt upgrade` changes nothing. Real remediation is a smaller base (distroless / Chainguard / Alpine). Live risk is limited: non-root, read-only rootfs, dropped caps, and most flagged packages (perl) are never executed at runtime. |
| 14 | **No rate limiting on authentication or search.** | Manual | **Medium** | `app/main.py` login, search | starter | Unlimited password guessing against `/auth/login`; unlimited expensive `LIKE '%...%'` scans. The share-link password path *is* rate-limited (per-link lockout added in Task 1), but nothing else is. Needs a reverse proxy / API gateway or middleware. |
| 15 | **Weak password policy.** `register` accepts any non-empty password. | Manual | **Low** | `app/main.py` register | starter | Users pick `pw`; combined with #14 (no lockout) online guessing is easy. |
| 16 | **IaC: secrets delivered as env vars, image not digest-pinned by default.** | Checkov (`CKV_K8S_35`, `CKV_K8S_43`) | **Low** | `helm/vulntracker-api` | [new] | Env-var secrets are visible in `/proc/<pid>/environ` and crash dumps; a mutable tag allows drift/rollback ambiguity. The chart already *supports* `image.digest`; making it mandatory and switching to file-mounted secrets is a small hardening step. |
| 17 | **Share-link lockout was permanent.** 10 wrong password attempts locked the link forever. | Manual (review of own Task 1 code) | **Medium** | `app/main.py` `GET /share/{token}` | [new] | Anyone who knows a shared link can submit 10 wrong passwords and permanently deny the intended auditor/customer access - a trivial denial-of-service against the feature. *(Fixed in Task 3: time-boxed lock.)* |
| 18 | **No database migration tooling.** Schema changes rely on `create_all`, which never alters existing tables. | Manual (hit while adding `locked_until`) | **Low** (prototype) / **High** (production) | `app/` | starter design | A persistent database silently diverges from the model after any column change - new writes 500. Acceptable while the store is a throwaway SQLite file; blocking for any real deployment. Needs Alembic. |

### False positives / non-issues (recorded so they are not re-raised)

| Finding | Source | Why it is not a finding |
|---------|--------|-------------------------|
| "Hardcoded secret being logged" at `main.py:367` | Semgrep `python-logger-credential-disclosure` | The log message for share-link creation merely contains the word "password" in a human string; no secret value is logged. |
| "ConfigMap with secrets" (`KSV-0109`, HIGH) | Trivy / Prowler IaC | The ConfigMap holds only non-secret config (`PUBLIC_BASE_URL`, `NOTIFY_SERVICE_URL`, prototype SQLite `DATABASE_URL`). Would become real if `DATABASE_URL` carried Postgres credentials - those are already routed through `secrets.items` instead. |
| "Workloads in the default namespace" (`KSV-0110` / `CKV_K8S_21`) | Trivy / Checkov IaC | Artifact of `helm template` without `-n`; the chart never hardcodes a namespace and `helm install` sets it. |
| "Restrict images to trusted registries" (`KSV-0125`) | Trivy IaC | `ghcr.io/<org>` is our own registry; the check has no configured allow-list. Informational. |
| `imagePullPolicy` should be `Always` (`CKV_K8S_15`) | Checkov IaC | With digest-pinned images, `IfNotPresent` is correct and avoids needless registry load. |
| Missing CSRF middleware in notify (`express-check-csurf...`) | Semgrep | The service is a token-less JSON API with no cookies/sessions; CSRF does not apply. The real problem is #5 (no auth at all). |

---

## Triage - fix order and why

| Pri | Finding(s) | Rationale |
| --- | ---------- | --------- |
| **P0** | #1 SQLi | single worst bug - full DB read/write from any account |
| **P0** | #2 JWT `none` + #3 `SECRET_KEY` | auth bypass; cheap to exploit, total impact; #9 compounds it |
| **P1** | #4 IDOR | same data-breach impact as #1, no skill needed |
| **P1** | #7 error/stack disclosure | multiplies exploitability of everything else |
| **P1** | #8 password logging | turns the log store into a credential store |
| **P1** | #5 + #6 notify no-auth + SSRF | unauthenticated path to cloud-metadata credential theft |
| **P1** | #17 permanent share-link lockout | trivial DoS against a delivered feature (in my own Task 1 code) |
| **P2** | #11–#13 dependency + base-image CVEs | mostly DoS / theoretical; higher effort, lower per-item impact |
| **P2** | #10 CORS, #14 rate limiting | defence-in-depth; #14 partly needs infra |
| **P3** | #15 password policy, #16 IaC hardening, #18 migrations (prototype) | low real-world impact given other controls |

---

## Remediation (Task 3)

Fixed in code - visible in the git diff, verified by tests and a re-scan
(`reports/after-fixes.*`):

| # | Finding | Change | Verified by |
|---|---------|--------|-------------|
| 1 | SQL injection in scan search | rewrote `search_scans_by_query` to a parameterised ORM query, scoped to the caller's `owner_id`, with LIKE wildcards escaped | `test_search_is_not_sql_injectable`, `test_search_is_scoped_to_owner`; Semgrep `avoid-sqlalchemy-text` gone |
| 2 | JWT `none` algorithm | `algorithms=[ALGORITHM]` only | `test_jwt_none_algorithm_is_rejected`; Semgrep `jwt-python-none-alg` gone |
| 3 | Hardcoded `SECRET_KEY` | removed the fallback; `config.py` aborts startup on a missing / weak / known-bad key. `DB_PASSWORD` / `ADMIN_API_KEY` defaults dropped too | startup check tested manually; `SECRET_KEY` now required in CI, compose, `.env.example` |
| 4 | IDOR on `GET /scans/{id}` | added `owner_id` filter | `test_get_scan_is_owner_scoped` |
| 7 | Stack traces to clients | global handler returns opaque `{"detail": "Internal server error"}`, logs the traceback server-side | manual |
| 8 | Passwords logged on login | log the username only | Semgrep `python-logger-credential-disclosure` down from 3 → 1 (remaining one is a false positive) |
| 9 / 11 | Vulnerable Python deps | `python-jose` 3.3.0 → 3.5.0, `cryptography` 38.0.1 → 50.0.1, removed unused `python-multipart` | SCA: `requirements.txt` 1 CRITICAL + 11 HIGH → **0 / 0** |
| 13 (partial) | build tooling shipped in image | `pip uninstall pip setuptools wheel` after install | container HIGH 50 → 35 |
| 17 | Share-link permanent lockout (my Task 1 code) | replaced the permanent lock with a **time-boxed** one (`locked_until`); added `Cache-Control: no-store` on shared responses | `test_share_link_locks_after_repeated_failures` (now also asserts auto-unlock), `test_share_link_create_and_public_access` |

**Scan deltas (before → after):**

| Scan | Before | After |
|------|--------|-------|
| SAST (Semgrep) | 7 | 3 (1 false positive + 2 in `notify/`) |
| SCA - `requirements.txt` | 1 CRITICAL, 11 HIGH | 0 CRITICAL, 0 HIGH (1 MEDIUM: `pytest`, test-only) |
| Container image | 6 CRITICAL, 50 HIGH | 5 CRITICAL, 35 HIGH (5 criticals are unfixable Debian base) |
| IaC | 3 | 3 (no chart changes this task) |

At least one fix (#17, and the `Cache-Control` addition) is in the Task 1 code.

**Not fixed** → [`remediation-plan.md`](remediation-plan.md): #5/#6 (notify auth +
SSRF), #10 (CORS), #12 + residual #11 (dependency bumps needing a framework
upgrade / `notify` changes), #13 (base-image re-base), #14 (rate limiting), #15
(password policy), #16 (IaC hardening).

---

## Positive findings

- The container image contains **no secrets** (Trivy secret scan clean) and both
  Dockerfiles pass all Trivy misconfig checks - the Step 1 hardening holds.
- The Helm chart passes the large majority of Trivy (403) and Checkov (86)
  policy checks; the residual items are low severity.
- The Task 1 share-link feature uses a 256-bit token stored only as a hash,
  bcrypt for the optional password, server-side expiry, and owner-only creation.
  The one issue found in it (#17, permanent lockout) was fixed in Task 3.
