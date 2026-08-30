# Security Automation Engineer — Take-Home Assignment

Welcome. This assignment is designed to reflect the real work of a Lead Security Automation Engineer: extending an existing service, identifying and assessing security risks, remediating them with code, and deploying it securely. There are no trick questions — we are evaluating your depth of knowledge, your judgment under constraints, and your ability to communicate risk.

**Estimated time: 4–6 hours.** We respect your time. If you find yourself going significantly over, scope down rather than rushing.

---

## Background

**VulnTracker** is a two-service system for managing vulnerability scan results:

- **`app/`** — Python/FastAPI REST API. Security teams use it to log findings, track remediation, and share reports with stakeholders.
- **`notify/`** — Node.js/Express notification service. Intended to dispatch webhook events to registered endpoints when scan records are created or updated.

Both services are working but imperfect internal prototypes. Neither has gone through a formal security review. The Python API calls the notification service in the background whenever a scan is created or updated — start both services to see the full flow.

---

## Getting Started

**Create your own repository for this assignment.** Do not fork — your solution must be in a fresh repo. You may use the starter code as a base, but your work must be in your own repo.

```bash
# 1. Clone the assignment repo locally
git clone https://github.com/cloudtriquetra/asa-assignment.git
cd asa-assignment

# 2. Point it at your own new GitHub repo (create one first at github.com)
git remote set-url origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

From here, work on your own repo and share its URL when you submit.

**Requirements:** Python 3.11 (exactly — see CI), Node.js 20+, Docker

**Python API (`app/`)**

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

The API must be started from inside the `app/` directory — the modules use bare imports and won't resolve from the repo root:

```bash
cd app
uvicorn main:app --reload
```

Available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

Run the Python test suite from the **repo root**:

```bash
pytest tests/ -v
```

**Notification Service (`notify/`)**

```bash
cd notify
npm install
npm start
```

Available at `http://localhost:3001`.

Run the Node.js test suite (stop the notify service first if it is running — the test suite starts its own server on the same port):

```bash
cd notify
npm test
```

---

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

Tools used (versions this run): Semgrep 1.175.0, Trivy 0.74.0, Prowler 5.40.0,
Checkov 3.3.16. All commands run from the repo root.

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

---

## Your Tasks

### Task 1 — Extend the App _(~1–1.5 hrs)_

Implement the **"Shared Report Link"** feature:

> As a VulnTracker user, I want to share a specific scan result with an external stakeholder (e.g. a customer or auditor) via a unique link. The link must expire after **24 hours** and must support **optional password protection**.

Add the following endpoints to the app:

| Method | Path                     | Auth          | Description                                                                                                              |
| ------ | ------------------------ | ------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `POST` | `/scans/{scan_id}/share` | Bearer token  | Generate a share token for a scan. Accepts optional `password` in the request body. Returns `{ "share_url": "..." }`     |
| `GET`  | `/share/{token}`         | None (public) | Return the scan data if the token is valid and not expired. If password-protected, require a `password` query parameter. |

Implementation choices are yours. We will read and evaluate the code you write here — including the security properties of your implementation. For the `share_url` value, use the incoming request's host, or hard-code `http://localhost:8000` for the prototype — document whichever you choose.

---

### Task 2 — Security Analysis _(~1.5 hrs)_

#### 2a. Run the required scans

You must run **all four** of the following scan categories. Select an appropriate open-source or free-tier tool for each — your tool choices are part of the evaluation.

| Scan type                                      | What it covers                                                                         |
| ---------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Static Application Security Testing (SAST)** | Source code — identify insecure coding patterns, injection risks, hardcoded secrets    |
| **Dependency / SCA vulnerability scan**        | Third-party packages — known CVEs in pinned dependencies                               |
| **Container image scan**                       | The Docker image you build — OS packages, installed libraries, misconfigurations       |
| **Infrastructure-as-Code (IaC) security scan** | Your Helm chart or Terraform — misconfigurations, insecure defaults, policy violations. Complete Task 4 first, then run this scan. |

Save the raw JSON output of each tool to the `reports/` directory, named clearly by scan type:

```
reports/
├── sast.<tool>.json
├── sca.<tool>.json
├── container.<tool>.json
└── iac.<tool>.json
```

#### 2b. Prioritised findings

Write a `docs/findings.md` with a table of security findings, sourced from your scans and your own manual review. For each finding:

- Tool and scan type that detected it (or "manual")
- Severity (your assessment — justify it)
- Business impact in the context of _this specific application_
- Whether it is in the starter code or in your new feature

**Do not copy-paste tool output.** We are evaluating your ability to interpret findings and apply business context to prioritisation — not your ability to run a command.

---

### Task 3 — Remediate _(~1 hr)_

- Fix **at least 3 critical or high severity findings** in code. Show the changes clearly (they will be visible in your git diff / PR).
- At least one fix must be in the code you wrote in Task 1.
- For findings you do not fix, document why in `docs/remediation-plan.md`: what is the residual risk, what effort would remediation require, and what compensating controls (if any) exist?

---

### Task 4 — Containerisation and Deployment Artifacts _(~30–45 min)_

#### Dockerfile (mandatory)

Write a production-grade `Dockerfile` for the **Python FastAPI service** (`app/`). It must:

- Use a minimal, pinned base image
- Run as a non-root user
- Include a `HEALTHCHECK`
- Not embed secrets or credentials

The container image must build successfully and the app must be reachable via `docker run`. Include build and run instructions in your README.

#### Infrastructure

Add either a `terraform/` or `helm/` directory (your choice) that could deploy this service to a Kubernetes cluster or cloud environment. Your deployment must:

- Source secrets from a secrets manager (not hardcoded in manifests or env vars)
- Restrict network ingress to only what is required
- Define resource limits and security contexts

---

### Task 5 — Executive Summary _(~30 min)_

Write `docs/executive-summary.md` as if you are presenting to a CISO who has 5 minutes.

Cover:

1. The overall security posture of the application before and after your work
2. The top 3 residual risks and the reason they were not fully remediated
3. Your recommended next steps if this were a real production service

No jargon. No tool names in the first paragraph. Your audience cares about business risk, not CVE numbers.

---

## Submission

Push your completed solution to your own GitHub repository and share the URL with us. Your repository must contain:

```
/
├── app/                        # extended Python API code
├── notify/                     # Node.js notification service (no changes required)
├── Dockerfile                  # mandatory (may cover one or both services)
├── reports/
│   ├── sast.<tool>.json
│   ├── sca.<tool>.json
│   ├── container.<tool>.json
│   └── iac.<tool>.json
├── terraform/  OR  helm/
├── docs/
│   ├── findings.md
│   ├── remediation-plan.md
│   └── executive-summary.md
├── tests/                      # updated if you added Python tests
└── README.md                   # update with Docker build/run instructions
```

CI must pass (green) on your repo before submission.

---

## What We Are Looking For

We are not grading on volume. We are grading on judgment.

- **Security depth**: Did you find the real issues? Did you prioritise them correctly for this application?
- **Implementation security**: Does your new feature introduce, or avoid, new vulnerabilities?
- **Remediation quality**: Are your fixes correct and complete? Are your deferral reasons honest?
- **Deployment security**: Does your container and infrastructure configuration reflect real-world security practices?
- **Communication**: Would a non-technical executive understand your summary?

Good luck. If anything in the brief is ambiguous, document your assumption and proceed.
