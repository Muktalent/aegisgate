"""Authentication, sessions, CSRF, RBAC and user administration."""
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

sys.path.append(str(Path(__file__).resolve().parents[1] / "backend"))

import app.main as api
from app import api_auth, passwords
from app.auth_models import SessionRecord, UserRecord
from app.db_models import AuditLogRecord
from security import SESSION_COOKIE, create_access_token, create_session_token

PASSWORD = "correct horse battery"
LOGIN = "/api/v1/auth/login"
ME = "/api/v1/auth/me"


def bearer(role="security_admin"):
    return {"Authorization": f"Bearer {create_access_token(username=f'test-{role}', role=role)}"}


@pytest.fixture
def isolated_api(tmp_path, monkeypatch):
    monkeypatch.setattr(passwords, "SCRYPT_N", 2 ** 12)       # fast hashing in tests
    monkeypatch.setattr(api_auth, "COOKIE_SECURE", False)   # the test client speaks plain HTTP
    api_auth.login_limiter.reset()
    test_engine = create_engine(
        f"sqlite:///{(tmp_path / 'auth_test.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(bind=test_engine)

    def override_get_db():
        with session_factory() as session:
            yield session

    previous_overrides = api.app.dependency_overrides.copy()
    monkeypatch.setattr(api, "engine", test_engine)
    api.app.dependency_overrides[api.get_db] = override_get_db
    try:
        with TestClient(api.app) as client:
            yield client, session_factory
    finally:
        api.app.dependency_overrides.clear()
        api.app.dependency_overrides.update(previous_overrides)
        test_engine.dispose()
        api_auth.login_limiter.reset()


def add_user(session_factory, username="analyst.one", role="soc_analyst", active=True):
    now = datetime.now(UTC)
    with session_factory() as session:
        session.add(UserRecord(
            username=username, password_hash=passwords.hash_password(PASSWORD), role=role,
            is_active=active, created_at=now, updated_at=now, last_login_at=None))
        session.commit()


def sign_in(client, username="analyst.one", password=PASSWORD):
    return client.post(LOGIN, json={"username": username, "password": password})


def audit_actions(session_factory):
    with session_factory() as session:
        return [row.action for row in session.scalars(
            select(AuditLogRecord).order_by(AuditLogRecord.audit_id)).all()]


# ---- sign-in -------------------------------------------------------------------

def test_login_sets_httponly_cookie_and_returns_no_token(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    response = sign_in(client)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["username"] == "analyst.one" and body["role"] == "soc_analyst" and body["csrf_token"]
    assert "access_token" not in body and "password" not in response.text
    cookie = response.headers["set-cookie"].lower()
    assert "aegis_session=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    me = client.get(ME)
    assert me.status_code == 200 and me.json()["username"] == "analyst.one"
    assert me.json()["csrf_token"] == body["csrf_token"]


def test_username_is_case_insensitive_and_trimmed(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    assert sign_in(client, "  Analyst.One ").status_code == 200


@pytest.mark.parametrize("username,password", [
    ("analyst.one", "wrong password here"), ("nobody.here", PASSWORD), ("disabled.user", PASSWORD)])
def test_invalid_credentials_get_the_same_answer(isolated_api, username, password):
    client, session_factory = isolated_api
    add_user(session_factory)
    add_user(session_factory, "disabled.user", active=False)
    response = sign_in(client, username, password)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username or password."}
    assert "set-cookie" not in response.headers
    assert client.get(ME).status_code == 401


def test_password_is_stored_hashed(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    with session_factory() as session:
        stored = session.get(UserRecord, "analyst.one").password_hash
    assert stored.startswith("scrypt$") and PASSWORD not in stored


def test_repeated_failures_are_rate_limited(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    for _ in range(5):
        assert sign_in(client, password="wrong password here").status_code == 401
    blocked = sign_in(client)                                   # correct password, still blocked
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) >= 1
    assert "login_rate_limited" in audit_actions(session_factory)


def test_sign_in_events_are_audited_without_passwords(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    sign_in(client, password="wrong password here")
    csrf = sign_in(client).json()["csrf_token"]
    assert client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert audit_actions(session_factory) == ["login_failed", "login_succeeded", "logout"]
    with session_factory() as session:
        for row in session.scalars(select(AuditLogRecord)).all():
            assert PASSWORD not in str(row.details_json) and "wrong password" not in str(row.details_json)


# ---- sessions and CSRF -----------------------------------------------------------

def test_protected_endpoints_reject_anonymous_requests(isolated_api):
    client, _ = isolated_api
    for path in (ME, "/api/v1/findings", "/api/v1/users", "/v1/events"):
        assert client.get(path).status_code == 401
    assert client.post("/api/v1/auth/logout").status_code == 401


def test_cookie_session_reads_and_csrf_protects_writes(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    csrf = sign_in(client).json()["csrf_token"]
    assert client.get("/api/v1/findings").status_code == 200
    missing = client.post("/api/v1/analysis/run")
    assert missing.status_code == 403 and missing.json()["detail"] == "CSRF token missing or invalid."
    assert client.post("/api/v1/analysis/run", headers={"X-CSRF-Token": "guess"}).status_code == 403
    assert client.post("/api/v1/analysis/run", headers={"X-CSRF-Token": csrf}).status_code == 200


def test_logout_invalidates_the_session_token(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    csrf = sign_in(client).json()["csrf_token"]
    token = client.cookies.get(SESSION_COOKIE)
    assert token
    assert client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    client.cookies.clear()
    replay = client.get(ME, headers={"Cookie": f"{SESSION_COOKIE}={token}"})
    assert replay.status_code == 401
    assert client.get(ME, headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_expired_tampered_and_unknown_sessions_are_rejected(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    now = datetime.now(UTC)
    with session_factory() as session:
        session.add(SessionRecord(session_id="expired-session", username="analyst.one",
                                  created_at=now - timedelta(hours=2),
                                  expires_at=now - timedelta(hours=1), revoked_at=None))
        session.commit()
    expired = create_session_token("analyst.one", "soc_analyst", "expired-session", "c",
                                   now - timedelta(hours=1))
    unknown = create_session_token("analyst.one", "soc_analyst", "no-such-session", "c",
                                   now + timedelta(minutes=5))
    sign_in(client)
    valid = client.cookies.get(SESSION_COOKIE)
    client.cookies.clear()
    for token in (expired, unknown, valid + "x", "not-a-token"):
        assert client.get(ME, headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_session_of_another_user_cannot_be_claimed(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    sign_in(client)
    with session_factory() as session:
        session_id = session.scalars(select(SessionRecord)).one().session_id
    forged = create_session_token("someone.else", "security_admin", session_id, "c",
                                  datetime.now(UTC) + timedelta(minutes=5))
    client.cookies.clear()
    assert client.get(ME, headers={"Authorization": f"Bearer {forged}"}).status_code == 401


# ---- roles ------------------------------------------------------------------------

def test_viewer_can_read_but_not_run_analysis_or_manage_users(isolated_api):
    client, _ = isolated_api
    assert client.get("/api/v1/findings", headers=bearer("viewer")).status_code == 200
    assert client.get("/api/v1/detections", headers=bearer("viewer")).status_code == 200
    assert client.post("/api/v1/analysis/run", headers=bearer("viewer")).status_code == 403
    assert client.get("/api/v1/users", headers=bearer("viewer")).status_code == 403


def test_only_administrators_manage_users(isolated_api):
    client, _ = isolated_api
    new_user = {"username": "new.analyst", "password": PASSWORD, "role": "soc_analyst"}
    for role in ("soc_analyst", "viewer", "ingestor"):
        assert client.post("/api/v1/users", headers=bearer(role), json=new_user).status_code == 403
    created = client.post("/api/v1/users", headers=bearer(), json=new_user)
    assert created.status_code == 201 and created.json()["role"] == "soc_analyst"
    assert "password" not in created.text
    assert client.post("/api/v1/users", headers=bearer(), json=new_user).status_code == 409
    assert sign_in(client, "new.analyst").status_code == 200
    listing = client.get("/api/v1/users", headers=bearer()).json()
    assert [item["username"] for item in listing["items"]] == ["new.analyst"]


@pytest.mark.parametrize("change", [
    {"password": "short"}, {"role": "superuser"}, {"username": "Bad Name"}, {"username": "ab"},
    {"username": "x'; DROP TABLE users;--"}])
def test_invalid_new_users_are_rejected(isolated_api, change):
    client, _ = isolated_api
    body = {"username": "new.analyst", "password": PASSWORD, "role": "viewer", **change}
    assert client.post("/api/v1/users", headers=bearer(), json=body).status_code == 422


def test_user_cannot_escalate_own_privileges(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    csrf = sign_in(client).json()["csrf_token"]
    response = client.patch("/api/v1/users/analyst.one", headers={"X-CSRF-Token": csrf},
                            json={"role": "security_admin"})
    assert response.status_code == 403
    with session_factory() as session:
        assert session.get(UserRecord, "analyst.one").role == "soc_analyst"


def test_administrator_cannot_demote_or_disable_self(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory, "root.admin", "security_admin")
    headers = {"X-CSRF-Token": sign_in(client, "root.admin").json()["csrf_token"]}
    assert client.patch("/api/v1/users/root.admin", headers=headers, json={"role": "viewer"}).status_code == 400
    assert client.patch("/api/v1/users/root.admin", headers=headers, json={"is_active": False}).status_code == 400
    assert client.patch("/api/v1/users/missing.user", headers=headers, json={"role": "viewer"}).status_code == 404


def test_role_change_revokes_existing_sessions_and_is_audited(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    sign_in(client)
    token = client.cookies.get(SESSION_COOKIE)
    client.cookies.clear()
    changed = client.patch("/api/v1/users/analyst.one", headers=bearer(), json={"role": "viewer"})
    assert changed.status_code == 200 and changed.json()["role"] == "viewer"
    assert client.get(ME, headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert sign_in(client).json()["role"] == "viewer"
    assert "user_updated" in audit_actions(session_factory)


def test_deactivated_user_cannot_sign_in_and_password_reset_works(isolated_api):
    client, session_factory = isolated_api
    add_user(session_factory)
    assert client.patch("/api/v1/users/analyst.one", headers=bearer(),
                        json={"is_active": False}).status_code == 200
    assert sign_in(client).status_code == 401
    assert client.patch("/api/v1/users/analyst.one", headers=bearer(),
                        json={"is_active": True, "password": "another long passphrase"}).status_code == 200
    assert sign_in(client).status_code == 401
    assert sign_in(client, password="another long passphrase").status_code == 200
