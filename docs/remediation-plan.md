# Remediation Plan - deferred findings

Findings from [`findings.md`](findings.md) that were **not** fixed in Task 3, why,
and what protects us in the meantime. Numbering matches `findings.md`.

---

### #5 / #6 - notify service has no auth + SSRF in webhook dispatch

- **Residual risk:** anyone who can reach `notify` registers a webhook pointing
  at `http://169.254.169.254/…` and reads cloud instance credentials; also
  internal port scanning and SSRF to internal-only services.
- **Effort:** medium. Add a shared-secret / mTLS check on `notify` endpoints, and
  an egress allow-list + private-IP/link-local block in `dispatcher.js`.
  Cross-service change; `notify/` is out of scope for code edits in this brief.
- **Compensating controls now:** the Helm `NetworkPolicy` restricts who can reach
  the API. Equivalent policy for `notify` plus a CNI-level block on
  `169.254.0.0/16` and RFC1918 egress is the interim mitigation. `notify` is a
  best-effort background service, not on the request path.

### #10 - CORS reflects arbitrary `Origin` with credentials

- **Residual risk:** any website can make credentialed cross-origin calls. Bounded
  because auth is a `Bearer` header, not an auto-sent cookie.
- **Effort:** low. Replace the reflecting middleware with `CORSMiddleware` and an
  explicit `allow_origins` list from config.
- **Compensating controls:** no cookie-based auth; tokens are short-lived (30 min).

### #11 / #12 - outstanding dependency CVEs

- **What's left after Task 3:** `starlette` (transitive via the pinned
  `fastapi==0.104.1`), `ecdsa` (transitive via `python-jose`, CVE-2024-23342
  Minerva - upstream won't fix), and the `notify` stack (`axios`,
  `path-to-regexp`, `body-parser`).
- **Residual risk:** mostly DoS; `ecdsa` timing attack is not reachable because
  the app signs with HS256, never ECDSA.
- **Effort:** medium. Bump `fastapi`/`starlette` together (API-compatible but
  needs a full test pass); migrate `python-jose` → `PyJWT` to drop `ecdsa`
  entirely; `npm audit fix` in `notify`.
- **Compensating controls:** HS256-only JWT config; `notify` DoS is non-critical.

### #13 - container base-image CVEs (5 CRITICAL, unfixable in Debian)

- **Residual risk:** low in practice - all are `will_not_fix` / deferred by
  Debian, and the flagged packages (`perl-base`, `util-linux`, …) are never
  executed by the app.
- **Effort:** medium. Re-base onto distroless / Chainguard and re-test the
  runtime (no shell, different libc edge cases).
- **Compensating controls:** non-root, read-only root FS, all capabilities
  dropped, no build tooling in the image, minimal package set.

### #14 - no rate limiting on `/auth/login` and `/scans/search`

- **Residual risk:** online password guessing; CPU exhaustion via repeated
  `LIKE '%…%'` scans.
- **Effort:** low–medium. Best done at the ingress / API gateway (per-IP limits)
  rather than app code; alternatively `slowapi` + Redis.
- **Compensating controls:** bcrypt work factor slows guessing; the share-link
  password path already has a time-boxed lockout.

### #15 - weak password policy, no email validation on registration

- **Residual risk:** users choose trivial passwords; malformed emails stored.
- **Effort:** low. `pydantic.EmailStr` + a min-length / complexity check in
  `UserRegister`.
- **Compensating controls:** none currently - depends on #14 for real protection.

### #18 - no database migration tooling

- **Residual risk:** any future schema change breaks a persistent database
  (`create_all` does not alter existing tables); writes start returning 500.
- **Effort:** low. Add Alembic, generate an initial revision from the current
  models, wire `alembic upgrade head` into container start / a Job.
- **Compensating controls:** the store is currently a throwaway SQLite file that
  is recreated on deploy; the issue only bites once data must survive.

### #16 - Helm: secrets as env vars, image tag not digest-pinned by default

- **Residual risk:** env-var secrets readable via `/proc/<pid>/environ` and crash
  dumps; a mutable tag allows ambiguous rollbacks.
- **Effort:** low. Mount the secret as a file and have the app read it; set
  `image.digest` as the documented required value.
- **Compensating controls:** dropped capabilities and read-only FS limit who can
  read `/proc`; the chart already supports `image.digest`.
