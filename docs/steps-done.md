# Steps Done

High-level log of changes per commit, plus considerations. Newest step at the bottom.

---

## Step 1 — Containerisation (initial repo analysis & part of Task 4)

- Containerised the FastAPI app — `Dockerfile`
- Containerised the notification service — `notify/Dockerfile`
- Created `docker-compose.yml` to run both together
- Parametrised `app/config.py` to read all settings from environment variables
  (dev fallbacks kept), added `.env.example` / `.dockerignore`, updated `README`

**Considerations:**
- During analysis I found config entries that are never referenced by the code
  (`DB_USER`, `DB_PASSWORD`, `ADMIN_API_KEY`). I kept them for now, but unified
  every config value to be parametrised via env vars for secure deployment.
- Hardcoded fallback secrets (`SECRET_KEY`, the above) are left in place on
  purpose — they are tracked security findings to remediate in a later step.

---

## Step 2 — Shared Report Links (Task 1)

- Added `POST /scans/{scan_id}/share` and `GET /share/{token}`
- New `ShareLink` model / `share_links` table
- Added tests for the feature; `README` documents the endpoints and choices

**Considerations:**
- `share_url` is built from a configured `PUBLIC_BASE_URL`, not the request
  `Host` header (Host is client-controlled → link-poisoning).
- Token is 256-bit random; only its SHA-256 hash is stored (DB leak ≠ live
  links). Fast hash is acceptable given the entropy.
- Optional password stored with bcrypt, constant-time verify, plus a per-link
  lockout after N failed attempts.
- Public response is a minimal view — omits `owner_id`, ids and
  `remediation_notes` (internal context).
- Only the scan owner can create a link; unknown / expired / valid tokens all
  return an identical 404 (no token oracle).
- Password may be sent via `X-Share-Password` header (preferred) or the
  `?password=` query param required by the brief.

---

## Step 3 — Helm chart (Task 4 · Infrastructure)

- Added `helm/vulntracker-api/` — a Helm chart deploying the FastAPI service
- Two secret backends, chosen via `secrets.provider` in `values.yaml`:
  - `eso` — renders an `ExternalSecret` (External Secrets Operator)
  - `avp` — renders a `Secret` with Argo CD Vault Plugin `<path:...>` placeholders
- `README` + chart `README` document usage

**Considerations:**
- No secret material in the chart. `Deployment` only consumes a k8s `Secret`;
  the provider templates differ, the workload spec doesn't. New secrets (e.g. a
  Postgres URL) are one entry in `secrets.items`.
- Deny-by-default `NetworkPolicy`: ingress only from the ingress-controller
  namespace to `:8000`; egress only to DNS + the notification service.
- Hardened pod/container: non-root uid 10001, read-only rootfs, drop ALL caps,
  no privilege escalation, `seccompProfile: RuntimeDefault`,
  `automountServiceAccountToken: false`.
- Resource requests/limits + startup/readiness/liveness probes on `/health`.
- Default `replicaCount: 1` — SQLite prototype store can't scale horizontally;
  called out in `NOTES.txt` and chart README, `persistence` toggle for a PVC.

---

## Step 4 — Security scans (Task 2a)

Ran all four scan categories; raw JSON in `reports/`, exact commands in the
README ("Security scans").

| Scan | Tool(s) → report |
| ---- | ---------------- |
| SAST | Semgrep → `sast.semgrep.json` |
| SCA | Trivy `fs` → `sca.trivy.json` |
| Container | Trivy `image` → `container.trivy.json` |
| IaC | Trivy `config`, Checkov, Prowler `iac` → `iac.{trivy,checkov,prowler}.json` (all kept) |

**Considerations:**
- SAST → Semgrep, not Trivy: Trivy has no code/taint analysis, and one Semgrep
  run covers both the Python API and the Node service.
- IaC → three tools kept (the brief doesn't cap it at one). Prowler `iac` turned
  out to shell out to the Trivy binary — identical findings (KSV-0109/0110/0125).
  Checkov is a separate engine and flagged more chart-specific issues (7 vs 3),
  incl. secrets-as-env-vars and image-not-pinned-by-digest. Trivy is primary,
  Checkov the second opinion; Prowler's real value is live cloud/cluster posture,
  not static linting.
- Both Dockerfiles scanned clean (0 findings) — validates Step 1.

Interpretation, prioritised findings table, triage and deferral rationale are in
`docs/findings.md` (Task 2b). Headline: 2 P0 code bugs (SQLi in `/scans/search`,
JWT `none` + hardcoded `SECRET_KEY`) and ~5 P1 (IDOR, stack-trace disclosure,
password logging, unauthenticated notify + SSRF). Most raw scan volume is
non-actionable (unfixable Debian base CVEs, transitive DoS).
