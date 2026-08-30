import os

# All settings are read from the environment so the service can be containerised
# and deployed without editing source. Non-secret values keep a sensible default;
# secrets have no default and the process refuses to start without them.

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vulntracker.db")

# --- JWT signing key (secret, required) ------------------------------------
# Remediation (finding #3): there is no hardcoded fallback any more. A missing or
# obviously-weak key aborts startup rather than silently signing tokens with a
# value that is public in git history.
_INSECURE_KEYS = {"", "v3ry-s3cr3t-jwt-k3y-do-not-share", "changeme", "secret"}
SECRET_KEY = os.environ.get("SECRET_KEY", "")
if SECRET_KEY in _INSECURE_KEYS or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECRET_KEY environment variable is missing or too weak (need >= 32 chars). "
        'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
    )

ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Database credentials — only needed once the app moves off SQLite. No default:
# absent means "not configured" rather than a fake value that looks real.
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

# Internal service API key (optional; absent = feature disabled).
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")

NOTIFY_SERVICE_URL = os.environ.get("NOTIFY_SERVICE_URL", "http://localhost:3001")

# Public base URL used to build shareable report links. Set this explicitly in
# every deployment: it is deliberately NOT derived from the request Host header,
# which is client-controlled and would allow an attacker to mint links that
# point at a domain they control.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000")

# Share-link password guessing: max wrong attempts before a temporary lock, and
# how long that lock lasts. The lock is time-boxed (finding #17) so a third party
# who knows a link cannot permanently deny the legitimate recipient access.
SHARE_LINK_MAX_FAILED_ATTEMPTS = int(
    os.environ.get("SHARE_LINK_MAX_FAILED_ATTEMPTS", "10")
)
SHARE_LINK_LOCK_MINUTES = int(os.environ.get("SHARE_LINK_LOCK_MINUTES", "15"))
