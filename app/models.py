from datetime import datetime, timedelta

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base

SHARE_LINK_TTL = timedelta(hours=24)


def _share_link_expiry() -> datetime:
    return datetime.utcnow() + SHARE_LINK_TTL


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("ScanResult", back_populates="owner")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    severity = Column(String(20), default="medium")   # critical | high | medium | low
    status = Column(String(20), default="open")        # open | in_progress | resolved
    cve_id = Column(String(30), nullable=True)
    affected_component = Column(String(200), nullable=False)
    remediation_notes = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="scans")
    share_links = relationship(
        "ShareLink", back_populates="scan", cascade="all, delete-orphan"
    )


class ShareLink(Base):
    """A time-limited, optionally password-protected public link to one scan.

    Security notes:
      * Only the SHA-256 hash of the token is stored, never the token itself, so
        a database disclosure does not hand out working links. SHA-256 (rather
        than a slow hash) is sufficient because the token carries ~256 bits of
        entropy and is therefore not brute-forceable.
      * The optional password is stored as a bcrypt hash (same context as user
        passwords) and checked in constant time.
      * ``failed_attempts`` + ``locked_until`` back a *time-boxed* lockout
        against password guessing. It is time-boxed rather than permanent
        (finding #17) so a third party who knows the link cannot lock the
        legitimate recipient out for good.
    """

    __tablename__ = "share_links"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    scan_id = Column(
        Integer, ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False, index=True
    )
    password_hash = Column(String(200), nullable=True)
    failed_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, default=_share_link_expiry, nullable=False)

    scan = relationship("ScanResult", back_populates="share_links")

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() >= self.expires_at

    @property
    def is_password_protected(self) -> bool:
        return self.password_hash is not None

    @property
    def is_locked(self) -> bool:
        return self.locked_until is not None and datetime.utcnow() < self.locked_until

    def register_failed_attempt(self, max_attempts: int, lock_minutes: int) -> None:
        """Count a wrong password; start a temporary lock once the limit is hit."""
        self.failed_attempts += 1
        if self.failed_attempts >= max_attempts:
            self.locked_until = datetime.utcnow() + timedelta(minutes=lock_minutes)
            self.failed_attempts = 0

    def reset_lock(self) -> None:
        self.failed_attempts = 0
        self.locked_until = None
