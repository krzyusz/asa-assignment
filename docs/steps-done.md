# Steps Done

High-level log of changes per commit, plus considerations. Newest step at the bottom.

---

## Step 1 — Containerisation

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
