from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import DATABASE_URL

# check_same_thread is a SQLite-only connect arg; passing it to other drivers errors.
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _escape_like(term: str) -> str:
    """Escape LIKE wildcards so user input can't widen the match."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search_scans_by_query(db, query: str, owner_id: int) -> list:
    """Case-insensitive substring search over a user's own scans.

    Finding #1: the previous implementation string-formatted ``query`` straight
    into raw SQL (SQL injection) and returned every user's rows. This version
    uses bound parameters via the ORM and is scoped to ``owner_id``.
    """
    from models import ScanResult  # local import avoids a circular import at module load

    pattern = f"%{_escape_like(query)}%"
    return (
        db.query(ScanResult)
        .filter(ScanResult.owner_id == owner_id)
        .filter(
            ScanResult.title.ilike(pattern, escape="\\")
            | ScanResult.description.ilike(pattern, escape="\\")
            | ScanResult.cve_id.ilike(pattern, escape="\\")
        )
        .all()
    )
