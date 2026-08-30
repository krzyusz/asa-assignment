import os

# All settings are overridable via environment variables so the service can be
# containerised and deployed without editing source. The literal fallbacks below
# are development-only conveniences — production deployments MUST supply real
# values (ideally from a secrets manager). Removing the insecure fallbacks is
# tracked as a remediation item.

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vulntracker.db")

SECRET_KEY = os.environ.get("SECRET_KEY", "v3ry-s3cr3t-jwt-k3y-do-not-share")
ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Database credentials (migrate to env vars before production deployment)
DB_USER = os.environ.get("DB_USER", "vulntracker_app")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "Tr@cker2024!")

# Internal service API key
ADMIN_API_KEY = os.environ.get(
    "ADMIN_API_KEY", "sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"
)

NOTIFY_SERVICE_URL = os.environ.get("NOTIFY_SERVICE_URL", "http://localhost:3001")

# Public base URL used to build shareable report links. Set this explicitly in
# every deployment: it is deliberately NOT derived from the request Host header,
# which is client-controlled and would allow an attacker to mint links that
# point at a domain they control.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000")

# Number of wrong-password attempts before a share link is locked.
SHARE_LINK_MAX_FAILED_ATTEMPTS = int(
    os.environ.get("SHARE_LINK_MAX_FAILED_ATTEMPTS", "10")
)
