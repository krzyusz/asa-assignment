import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import models
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import (
    NOTIFY_SERVICE_URL,
    PUBLIC_BASE_URL,
    SHARE_LINK_LOCK_MINUTES,
    SHARE_LINK_MAX_FAILED_ATTEMPTS,
)
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Finding #7: the traceback / exception detail is logged server-side only.
    # Clients get an opaque 500 so we don't leak paths, versions or SQL fragments.
    logger.exception("Unhandled exception on %s", request.url)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cve_id: Optional[str] = None
    affected_component: str
    remediation_notes: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = None


class ScanOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ShareCreate(BaseModel):
    # bcrypt only considers the first 72 bytes; reject longer input explicitly
    # rather than silently truncating. A minimum length gives brute-force
    # resistance some help beyond the lockout counter.
    password: Optional[str] = Field(default=None, min_length=8, max_length=72)


class ShareOut(BaseModel):
    share_url: str
    expires_at: datetime
    password_protected: bool


class SharedScanOut(BaseModel):
    """Deliberately minimal view handed to external stakeholders.

    Excludes internal-only fields: database ids, ``owner_id`` and
    ``remediation_notes`` (which may contain sensitive internal context).
    """

    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_share_token(token: str) -> str:
    """Hash a raw share token for storage / lookup.

    SHA-256 is adequate here (unlike for passwords) because the token is a
    256-bit random value and cannot be brute-forced.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    # Finding #8: never log the submitted password.
    logger.info("Login attempt for username: %s", payload.username)
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning("Failed login for username: %s", payload.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search", response_model=List[ScanOut])
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    # Finding #1: parameterised and scoped to the caller's own scans.
    return search_scans_by_query(db, q, owner_id=current_user.id)


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Finding #4: filter by owner so users can't read each other's scans by id.
    scan = (
        db.query(models.ScanResult)
        .filter(
            models.ScanResult.id == scan_id,
            models.ScanResult.owner_id == current_user.id,
        )
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------

@app.post("/scans/{scan_id}/share", response_model=ShareOut, status_code=201)
def create_share_link(
    scan_id: int,
    payload: ShareCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Mint a 24h public link to one scan, optionally password-protected.

    Only the scan owner may share it. The raw token is returned exactly once,
    embedded in ``share_url``; only its hash is persisted.
    """
    scan = (
        db.query(models.ScanResult)
        .filter(
            models.ScanResult.id == scan_id,
            models.ScanResult.owner_id == current_user.id,
        )
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    raw_token = secrets.token_urlsafe(32)
    link = models.ShareLink(
        token_hash=_hash_share_token(raw_token),
        scan_id=scan.id,
        password_hash=(
            get_password_hash(payload.password) if payload.password else None
        ),
        created_by=current_user.id,
    )
    db.add(link)
    db.commit()
    db.refresh(link)

    logger.info(
        "Share link %s created for scan %s by user %s (password_protected=%s)",
        link.id, scan.id, current_user.username, link.is_password_protected,
    )

    share_url = f"{PUBLIC_BASE_URL.rstrip('/')}/share/{raw_token}"
    return ShareOut(
        share_url=share_url,
        expires_at=link.expires_at,
        password_protected=link.is_password_protected,
    )


@app.get("/share/{token}", response_model=SharedScanOut)
def get_shared_scan(
    token: str,
    response: Response,
    password: Optional[str] = Query(default=None),
    x_share_password: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """Public: resolve a share token to a minimal scan view.

    The password may be supplied via the ``X-Share-Password`` header (preferred,
    as it stays out of access logs / browser history) or the ``password`` query
    parameter. Missing, expired and unknown tokens all return an identical 404
    so the endpoint cannot be used to probe for valid tokens.
    """
    link = (
        db.query(models.ShareLink)
        .filter(models.ShareLink.token_hash == _hash_share_token(token))
        .first()
    )
    if link is None or link.is_expired:
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    if link.is_password_protected:
        if link.is_locked:
            raise HTTPException(
                status_code=429,
                detail="Too many incorrect password attempts; try again later",
            )
        supplied = x_share_password or password
        if not supplied:
            raise HTTPException(
                status_code=401,
                detail="This report is password protected",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not verify_password(supplied, link.password_hash):
            # Finding #17: temporary lock, not a permanent one.
            link.register_failed_attempt(
                SHARE_LINK_MAX_FAILED_ATTEMPTS, SHARE_LINK_LOCK_MINUTES
            )
            db.commit()
            raise HTTPException(status_code=401, detail="Incorrect password")
        if link.failed_attempts or link.locked_until:
            link.reset_lock()
            db.commit()

    scan = (
        db.query(models.ScanResult)
        .filter(models.ScanResult.id == link.scan_id)
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    # Shared vulnerability data must not be cached by browsers or proxies.
    response.headers["Cache-Control"] = "no-store"
    logger.info("Share link %s accessed for scan %s", link.id, link.scan_id)
    return scan


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}
