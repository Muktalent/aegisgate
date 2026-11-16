import hmac
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    ENVIRONMENT,
    INGESTOR_PASSWORD,
    INGESTOR_USERNAME,
    JWT_ALGORITHM,
    JWT_SECRET,
    SOC_PASSWORD,
    SOC_USERNAME,
)


bearer_scheme = HTTPBearer(auto_error=False)

SESSION_COOKIE = "aegis_session"
CSRF_HEADER = "X-CSRF-Token"
COOKIE_SECURE = ENVIRONMENT == "production"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


LAB_USERS = {
    INGESTOR_USERNAME: {
        "password": INGESTOR_PASSWORD,
        "role": "ingestor",
    },
    SOC_USERNAME: {
        "password": SOC_PASSWORD,
        "role": "soc_analyst",
    },
    ADMIN_USERNAME: {
        "password": ADMIN_PASSWORD,
        "role": "security_admin",
    },
}


def authenticate_lab_user(username: str, password: str) -> dict | None:
    user = LAB_USERS.get(username)

    if user is None or user["password"] != password:
        return None

    return {
        "username": username,
        "role": user["role"],
    }


def create_access_token(username: str, role: str) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_session_token(
    username: str,
    role: str,
    session_id: str,
    csrf_token: str,
    expires_at: datetime,
) -> str:
    """Token for a browser session. ``sid`` ties it to a server-side session
    record, so signing out or changing the user invalidates it."""
    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.now(UTC),
        "exp": expires_at,
        "sid": session_id,
        "csrf": csrf_token,
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _unauthorised(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_identity(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    """Accept a bearer token (services, tests) or the HttpOnly session cookie
    (browser). Cookie requests that change state must also send the CSRF
    token issued at sign-in."""
    from_cookie = False

    if credentials is not None:
        token = credentials.credentials
    else:
        token = request.cookies.get(SESSION_COOKIE)
        from_cookie = token is not None

    if not token:
        raise _unauthorised("Bearer authentication is required.")

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
    except jwt.PyJWTError as exc:
        raise _unauthorised("Invalid or expired access token.") from exc

    username = payload.get("sub")
    role = payload.get("role")

    if not isinstance(username, str) or not isinstance(role, str):
        raise _unauthorised("Access token has an invalid identity payload.")

    session_id = payload.get("sid")

    if session_id is not None:
        from app.auth_models import SessionRecord

        record = db.get(SessionRecord, session_id) if isinstance(session_id, str) else None

        if record is None or record.revoked_at is not None or record.username != username:
            raise _unauthorised("Invalid or expired access token.")

    csrf_token = payload.get("csrf")

    if from_cookie and request.method not in SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, "")

        if (
            not isinstance(csrf_token, str)
            or not csrf_token
            or not hmac.compare_digest(supplied.encode("utf-8"), csrf_token.encode("utf-8"))
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token missing or invalid.",
            )

    return {
        "username": username,
        "role": role,
        "session_id": session_id if isinstance(session_id, str) else None,
        "csrf_token": csrf_token if isinstance(csrf_token, str) else None,
    }


def require_roles(*allowed_roles: str):
    def role_guard(
        identity: Annotated[dict, Depends(get_current_identity)],
    ) -> dict:
        if identity["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your role is not authorised for this operation.",
            )

        return identity

    return role_guard
