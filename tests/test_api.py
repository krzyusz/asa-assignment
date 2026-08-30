import os
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402
from models import ShareLink  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_jwt_none_algorithm_is_rejected():
    import base64
    import json as _json

    register_and_login("alice", "alice@example.com")

    def b64(obj):
        return base64.urlsafe_b64encode(_json.dumps(obj).encode()).rstrip(b"=").decode()

    forged = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'alice'})}."
    resp = client.get("/scans", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["title"] == "SQL Injection via login"


def test_search_is_scoped_to_owner():
    alice = register_and_login("alice", "alice@example.com")
    client.post("/scans", json={
        "title": "alice secret finding", "severity": "high", "affected_component": "x",
    }, headers=auth_headers(alice))
    bob = register_and_login("bob", "bob@example.com")
    resp = client.get("/scans/search?q=secret", headers=auth_headers(bob))
    assert resp.status_code == 200
    assert resp.json() == []


def test_search_is_not_sql_injectable():
    token = register_and_login()
    client.post("/scans", json={
        "title": "benign", "severity": "low", "affected_component": "x",
    }, headers=auth_headers(token))
    # Classic payload — must be treated as a literal substring, not SQL.
    resp = client.get("/scans/search", params={"q": "' OR '1'='1"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json() == []
    # A bare LIKE wildcard must not act as a wildcard either.
    resp = client.get("/scans/search", params={"q": "%%"}, headers=auth_headers(token))
    assert resp.json() == []


def test_get_scan_is_owner_scoped():
    alice = register_and_login("alice", "alice@example.com")
    scan_id = client.post("/scans", json={
        "title": "alice only", "severity": "high", "affected_component": "x",
    }, headers=auth_headers(alice)).json()["id"]
    bob = register_and_login("bob", "bob@example.com")
    assert client.get(f"/scans/{scan_id}", headers=auth_headers(bob)).status_code == 404
    assert client.get(f"/scans/{scan_id}", headers=auth_headers(alice)).status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------

def _make_scan(token, **overrides):
    body = {"title": "Shared finding", "severity": "high", "affected_component": "api"}
    body.update(overrides)
    return client.post("/scans", json=body, headers=auth_headers(token)).json()["id"]


def _token_from_url(share_url):
    return share_url.rsplit("/", 1)[1]


def test_share_link_create_and_public_access():
    token = register_and_login()
    scan_id = _make_scan(token, description="internal detail", remediation_notes="secret plan")

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 201
    body = resp.json()
    assert body["share_url"].endswith(f"/share/{_token_from_url(body['share_url'])}")
    assert body["password_protected"] is False

    public = client.get(f"/share/{_token_from_url(body['share_url'])}")
    assert public.status_code == 200
    assert public.headers.get("cache-control") == "no-store"
    data = public.json()
    assert data["title"] == "Shared finding"
    # minimal disclosure — internal fields must not leak
    assert "owner_id" not in data
    assert "remediation_notes" not in data
    assert "id" not in data


def test_share_link_requires_scan_ownership():
    owner = register_and_login("owner", "owner@example.com")
    scan_id = _make_scan(owner)
    attacker = register_and_login("attacker", "attacker@example.com")

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(attacker))
    assert resp.status_code == 404


def test_share_link_unknown_token_is_404():
    resp = client.get("/share/does-not-exist")
    assert resp.status_code == 404


def test_share_link_expired_is_404():
    token = register_and_login()
    scan_id = _make_scan(token)
    share_url = client.post(
        f"/scans/{scan_id}/share", json={}, headers=auth_headers(token)
    ).json()["share_url"]

    db = TestingSessionLocal()
    link = db.query(ShareLink).one()
    link.expires_at = datetime.utcnow() - timedelta(minutes=1)
    db.commit()
    db.close()

    resp = client.get(f"/share/{_token_from_url(share_url)}")
    assert resp.status_code == 404


def test_share_link_password_protection():
    token = register_and_login()
    scan_id = _make_scan(token)
    share_url = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "correct horse"},
        headers=auth_headers(token),
    ).json()["share_url"]
    tok = _token_from_url(share_url)

    assert client.get(f"/share/{tok}").status_code == 401
    assert client.get(f"/share/{tok}", params={"password": "wrong"}).status_code == 401
    assert client.get(f"/share/{tok}", params={"password": "correct horse"}).status_code == 200
    assert client.get(
        f"/share/{tok}", headers={"X-Share-Password": "correct horse"}
    ).status_code == 200


def test_share_link_locks_after_repeated_failures():
    token = register_and_login()
    scan_id = _make_scan(token)
    share_url = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "correct horse"},
        headers=auth_headers(token),
    ).json()["share_url"]
    tok = _token_from_url(share_url)

    for _ in range(10):
        assert client.get(f"/share/{tok}", params={"password": "wrong"}).status_code == 401

    # locked now — even the correct password is refused
    assert client.get(f"/share/{tok}", params={"password": "correct horse"}).status_code == 429

    # ...but the lock is time-boxed (finding #17): once it lapses, access returns.
    db = TestingSessionLocal()
    link = db.query(ShareLink).one()
    link.locked_until = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    db.close()
    assert client.get(f"/share/{tok}", params={"password": "correct horse"}).status_code == 200


def test_share_link_rejects_short_password():
    token = register_and_login()
    scan_id = _make_scan(token)
    resp = client.post(
        f"/scans/{scan_id}/share", json={"password": "short"}, headers=auth_headers(token)
    )
    assert resp.status_code == 422
