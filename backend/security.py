from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    INGESTOR_PASSWORD,
    INGESTOR_USERNAME,
    JWT_ALGORITHM,
    JWT_SECRET,
    SOC_PASSWORD,
    SOC_USERNAME,
)


bearer_scheme = HTTPBearer(auto_error=False)


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


def get_current_identity(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
) -> dict:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    username = payload.get("sub")
    role = payload.get("role")

    if not isinstance(username, str) or not isinstance(role, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has an invalid identity payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "username": username,
        "role": role,
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