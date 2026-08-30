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
  