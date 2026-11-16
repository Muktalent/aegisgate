"""Sign-in, sign-out, current user and user administration (AG-01)."""
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app import passwords
from app.auth_models import ROLES, SessionRecord, UserRecord
from app.database import get_db
from app.db_models import AuditLogRecord
from app.rate_limit import FailureRateLimiter
from config import ACCESS_TOKEN_EXPIRE_MINUTES, JWT_SECRET
from security import (
    COOKIE_SECURE,
    SESSION_COOKIE,
    create_session_token,
    get_current_identity,
    require_roles,
)

router = APIRouter(prefix="/api/v1", tags=["auth"])

USERNAME_PATTERN = r"^[a-z0-9][a-z0-9._@-]{2,63}$"
login_limiter = FailureRateLimiter(max_failures=5, window_seconds=300)
_dummy_hash: str | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class CreateUserRequest(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    password: str = Field(min_length=1, max_length=256)
    role: str


class UpdateUserRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=1, max_length=256)


def _audit(db: Session, actor: str, action: str, target: str, details: dict[str, Any]) -> None:
    db.add(AuditLogRecord(
        occurred_at=datetime.now(UTC), actor=actor[:128], action=action,
        target_type="user", target_id=target[:255], details_json=details))


def _user(row: UserRecord) -> dict[str, Any]:
    def iso(value: datetime | None) -> str | None:
        if value is None:
            return None
        return (value if value.tzinfo else value.replace(tzinfo=UTC)).isoformat()

    return {"username": row.username, "role": row.role, "is_active": row.is_active,
            "created_at": iso(row.created_at), "last_login_at": iso(row.last_login_at)}


def _revoke_sessions(db: Session, username: str) -> None:
    db.execute(update(SessionRecord)
               .where(SessionRecord.username == username, SessionRecord.revoked_at.is_(None))
               .values(revoked_at=datetime.now(UTC)))


def _check_new_password(password: str) -> None:
    try:
        passwords.validate_new_password(password)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise HTTPException(status_code=422, detail=f"Role must be one of: {', '.join(ROLES)}.")


@router.post("/auth/login")
def login(body: LoginRequest, request: Request, response: Response,
          db: Session = Depends(get_db)) -> dict:
    global _dummy_hash

    if not JWT_SECRET:
        raise HTTPException(status_code=503, detail="Authentication is not configured on this server.")

    username = body.username.strip().lower()
    client = request.client.host if request.client else "unknown"
    key = (username, client)
    wait = login_limiter.retry_after(key)

    if wait:
        _audit(db, username, "login_rate_limited", username, {"client": client})
        db.commit()
        raise HTTPException(status_code=429, detail="Too many failed sign-in attempts. Try again later.",
                            headers={"Retry-After": str(wait)})

    user = db.get(UserRecord, username)

    if user is None:
        # Spend the same hashing time for unknown users.
        if _dummy_hash is None:
            _dummy_hash = passwords.hash_password(secrets.token_urlsafe(16))
        passwords.verify_password(body.password, _dummy_hash)
        valid = False
    else:
        valid = passwords.verify_password(body.password, user.password_hash) and user.is_active

    if not valid:
        login_limiter.record_failure(key)
        _audit(db, username, "login_failed", username, {"client": client})
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    login_limiter.reset(key)
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    session = SessionRecord(session_id=uuid4().hex, username=user.username, created_at=now,
                            expires_at=expires_at, revoked_at=None)
    csrf_token = secrets.token_urlsafe(32)
    token = create_session_token(user.username, user.role, session.session_id, csrf_token, expires_at)

    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(body.password)

    user.last_login_at = now
    db.add(session)
    _audit(db, user.username, "login_succeeded", user.username, {"client": client, "role": user.role})
    db.commit()

    response.set_cookie(
        SESSION_COOKIE, token, max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60, path="/",
        httponly=True, samesite="strict", secure=COOKIE_SECURE)

    return {"username": user.username, "role": user.role, "csrf_token": csrf_token,
            "expires_at": expires_at.isoformat()}


@router.post("/auth/logout")
def logout(response: Response, db: Session = Depends(get_db),
           identity: dict = Depends(get_current_identity)) -> dict:
    if identity["session_id"]:
        record = db.get(SessionRecord, identity["session_id"])
        if record is not None and record.revoked_at is None:
            record.revoked_at = datetime.now(UTC)
    _audit(db, identity["username"], "logout", identity["username"], {})
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "signed_out"}


@router.get("/auth/me")
def current_user(identity: dict = Depends(get_current_identity)) -> dict:
    return {"username": identity["username"], "role": identity["role"],
            "csrf_token": identity["csrf_token"]}


@router.get("/users")
def list_users(db: Session = Depends(get_db),
               identity: dict = Depends(require_roles("security_admin"))) -> dict:
    rows = db.scalars(select(UserRecord).order_by(UserRecord.username)).all()
    return {"total": len(rows), "items": [_user(row) for row in rows]}


@router.post("/users", status_code=201)
def create_user(body: CreateUserRequest, db: Session = Depends(get_db),
                identity: dict = Depends(require_roles("security_admin"))) -> dict:
    _check_role(body.role)
    _check_new_password(body.password)

    if db.get(UserRecord, body.username) is not None:
        raise HTTPException(status_code=409, detail="A user with this username already exists.")

    now = datetime.now(UTC)
    row = UserRecord(username=body.username, password_hash=passwords.hash_password(body.password),
                     role=body.role, is_active=True, created_at=now, updated_at=now, last_login_at=None)
    db.add(row)
    _audit(db, identity["username"], "user_created", body.username, {"role": body.role})
    db.commit()
    return _user(row)


@router.patch("/users/{username}")
def update_user(username: str, body: UpdateUserRequest, db: Session = Depends(get_db),
                identity: dict = Depends(require_roles("security_admin"))) -> dict:
    row = db.get(UserRecord, username)

    if row is None:
        raise HTTPException(status_code=404, detail="User not found.")

    is_self = username == identity["username"]
    changes: dict[str, Any] = {}

    if body.role is not None and body.role != row.role:
        _check_role(body.role)
        if is_self:
            raise HTTPException(status_code=400, detail="You cannot change your own role.")
        changes["role"] = {"from": row.role, "to": body.role}
        row.role = body.role

    if body.is_active is not None and body.is_active != row.is_active:
        if is_self:
            raise HTTPException(status_code=400, detail="You cannot deactivate your own account.")
        changes["is_active"] = body.is_active
        row.is_active = body.is_active

    if body.password is not None:
        _check_new_password(body.password)
        row.password_hash = passwords.hash_password(body.password)
        changes["password"] = "changed"

    if changes:
        row.updated_at = datetime.now(UTC)
        if not is_self:
            _revoke_sessions(db, username)      # existing sessions carry the old role
        _audit(db, identity["username"], "user_updated", username, changes)
        db.commit()

    return _user(row)
