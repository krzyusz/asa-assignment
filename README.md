# VulnTracker assignment

## Background

**VulnTracker** is a two-service system for managing vulnerability scan results:

- **`app/`** — Python/FastAPI REST API. Security teams use it to log findings, track remediation, and share reports with stakeholders.
- **`notify/`** — Node.js/Express notification service. Intended to dispatch webhook events to registered endpoints when scan records are created or updated.

Both services are working but imperfect internal prototypes. Neither has gone through a formal security review. The Python API calls the notification service in the background whenever a scan is created or updated — start both services to see the full flow.


## Run with Docker

Two images are provided:

| Image | Dockerfile | Base (pinned by tag + digest) | Runs as |
| ----- | ---------- | ----------------------------- | ------- |
| `vulntracker-api` (mandatory) | `./Dockerfile` | `python:3.11-slim-bookworm` | `appuser` (uid 10001) |
| `vulntracker-notify` | `./notify/Dockerfile` | `node:20-bookworm-slim` | `node` (uid 1000) |

Both are multi-stage, run as a non-root user, ship a `HEALTHCHECK`, use `tini` as
init, and contain **no secrets** — all configuration is read from environment
variables (`app/config.py` now sources everything from `os.environ`, with
development-only fallbacks). The build context is the repo root for both.

### Just the API

```bash
docker build -t vulntracker-api .

docker run --rm -p 8000:8000 \
  -e SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  vulntracker-api
```

`SECRET_KEY` is the only required variable. The SQLite database is written to
`/data` (declared as a `VOLUME`) so the container's root filesystem can stay
read-only; add `-v vulntracker-data:/data` to persist it across runs.

Check it:

```bash
curl -fsS localhost:8000/health          # {"status":"ok","service":"vulntracker-api"}
docker inspect --format '{{.State.Health.Status}}' <container>   # healthy
```

### Full stack (API + notification service)

Runs both services on a private bridge network so you can watch the end-to-end
flow (create a scan → the API calls the notification service in the background).

```bash
cp .env.example .env
#  edit .env and set SECRET_KEY  (python -c 'import secrets; print(secrets.token_urlsafe(48))')

docker compose up --build
```

- Published ports are bound to `127.0.0.1` only: API on `:8000`, notify on
  `:3001` (the latter exposed purely for hands-on exploration — delete the
  `ports:` block to make it fully internal). Override with `API_PORT` /
  `NOTIFY_PORT` in `.env` if those ports are taken.
- Each service runs with a read-only root FS, `cap_drop: ALL`,
  `no-new-privileges`, and CPU/memory limits.

Walk the flow:

```bash
BASE=http://localhost:8000
curl -s -X POST $BASE/auth/register -H 'content-type: application/json' \
  -d '{"username":"alice","email":"a@example.com","password":"pw12345"}'
TOKEN=$(curl -s -X POST $BASE/auth/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"pw12345"}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST $BASE/scans -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"title":"Test XSS","severity":"high","affected_component":"GET /search"}'

docker compose logs app | grep notify:3001   # shows the background call to the notification service
```

Tear down: `docker compose down -v`.

### Notes / assumptions

- **Prototype scope**: the SQLite DB and the notification service's in-memory
  webhook registry are prototype stores, not production persistence.
- **Secrets**: `app/config.py` now fails closed — the process refuses to start
  without a strong `SECRET_KEY` (Task 3). `notify/src/config.js` still carries a
  hardcoded `SERVICE_KEY`; `notify/` is out of scope for code changes (see
  `docs/remediation-plan.md`).
- The Node test suite requires Node 20+ (per CI); on older local Node it may fail
  to connect in its `before` hook.

---

## Shared Report Links (Task 1)

Two endpoints let an owner share a single scan with an external stakeholder:

| Method | Path | Auth | Notes |
| ------ | ---- | ---- | ----- |
| `POST` | `/scans/{scan_id}/share` | Bearer | Body: optional `{"password": "..."}` (8–72 chars). Returns `{ "share_url", "expires_at", "password_protected" }`. Only the scan **owner** may share. |
| `GET`  | `/share/{token}` | Public | Returns a minimal scan view. Password (if set) via `X-Share-Password` header (preferred) or `?password=`. |

Example:

```bash
curl -s -X POST $BASE/scans/1/share -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"password":"correct horse"}'
# { "share_url": "http://localhost:8000/share/<token>", "expires_at": "...", "password_protected": true }

curl -s "$BASE/share/<token>" -H 'X-Share-Password: correct horse'
```

Design choices (the "production-mature" option was taken at each fork):

- **Link lifetime**: 24h, enforced server-side (`ShareLink.expires_at`).
- **`share_url` host**: built from the configured `PUBLIC_BASE_URL`, **not** the
  request `Host` header (which is client-controlled and would allow minting
  links pointing at an attacker domain). Set `PUBLIC_BASE_URL` per environment;
  it defaults to `http://localhost:8000` for the prototype.
- **Token**: 256-bit `secrets.token_urlsafe(32)`, returned once. Only its
  **SHA-256 hash** is stored, so a DB leak yields no usable links. A fast hash
  is fine because the token is high-entropy.
- **Password**: bcrypt (same context as user passwords), constant-time verify,
  plus a per-link lockout after `SHARE_LINK_MAX_FAILED_ATTEMPTS` (default 10).
- **Minimal disclosure**: the public view omits `owner_id`, database ids and
  `remediation_notes` (potentially sensitive internal context).
- **No token oracle**: unknown, expired and (pre-auth) valid tokens all return
  an identical `404`.

New table `share_links` is created automatically on startup (no migrations in
this prototype).

---

## Deploy to Kubernetes

A Helm chart for the API lives in [`helm/vulntracker-api/`](helm/vulntracker-api/)
(see its README for full detail).

```bash
helm install vulntracker ./helm/vulntracker-api \
  --namespace vulntracker --create-namespace \
  --set image.repository=<registry>/vulntracker-api --set image.digest=sha256:... \
  --set config.PUBLIC_BASE_URL=https://vulntracker.example.com \
  --set ingress.enabled=true --set ingress.host=vulntracker.example.com
```

**Secrets** are never in the chart. `secrets.provider` selects how the
`SECRET_KEY` Secret is populated:

- `eso` (default) — renders an `ExternalSecret`; External Secrets Operator syncs
  it from your `SecretStore`.
- `avp` — renders a `Secret` of `<path:...>` placeholders for the Argo CD Vault
  Plugin to resolve.

The `Deployment` is identical either way. Additional secrets (e.g. a Postgres
URL) are one line in `secrets.items`.

**Also included:** non-root / read-only-rootfs / dropped-capabilities security
contexts, a deny-by-default `NetworkPolicy` (ingress only from the ingress
controller, egress only to DNS + the notification service), resource
requests/limits, and `/health` probes.

---

## Security scans

Raw JSON output for every scan is committed under [`reports/`](reports/), with
`reports/after-fixes.*` from a re-scan after the Task 3 remediation.
Interpretation and prioritisation are in [`docs/findings.md`](docs/findings.md);
deferred items in [`docs/remediation-plan.md`](docs/remediation-plan.md).

SAST, SCA, container and IaC scans also run in CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) — each job uploads its
JSON as a build artifact and fails the build on new CRITICAL/HIGH issues in
first-party code (scope and thresholds: `docs/steps-done.md`, Step 7).

Tools used (versions this run): Semgrep 1.175.0, Trivy 0.74.0, Prowler 5.40.0,
Checkov 3.3.16. All commands below run from the repo root.

### SAST — Semgrep → `reports/sast.semgrep.json`

```bash
semgrep scan \
  --config p/default --config p/python --config p/javascript \
  --config p/security-audit --config p/owasp-top-ten --config p/secrets \
  --config p/jwt --config p/command-injection --config p/sql-injection \
  --config p/insecure-transport \
  --metrics off --json -o reports/sast.semgrep.json \
  app/ notify/src/ tests/
```

### SCA — Trivy → `reports/sca.trivy.json`

```bash
trivy fs --scanners vuln --format json -o reports/sca.trivy.json .
```

### Container image — Trivy → `reports/container.trivy.json`

```bash
docker build -t vulntracker-api:local .
trivy image --scanners vuln,secret --format json \
  -o reports/container.trivy.json vulntracker-api:local
```

### IaC — three tools (all reports kept)

```bash
# Trivy (primary) — also scans both Dockerfiles
trivy config --format json -o reports/iac.trivy.json .

# Checkov — broader K8s policy set, used as a second opinion
checkov -d helm/vulntracker-api --framework helm -o json --quiet \
  > reports/iac.checkov.json

# Prowler (needs the trivy binary on PATH — its iac provider wraps Trivy)
prowler iac --scan-path helm/vulntracker-api --scanners misconfig secret \
  --output-formats json-ocsf --output-filename iac.prowler \
  --output-directory reports --no-banner --ignore-exit-code-3
mv reports/iac.prowler.ocsf.json reports/iac.prowler.json
```

CI must pass (green) on your repo before submission.

---
