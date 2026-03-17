from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings
from app.models.enums import UserRole

security_scheme = HTTPBearer(auto_error=False)

ROLE_ORDER = {
    UserRole.VIEWER: 1,
    UserRole.ANALYST: 2,
    UserRole.ADMIN: 3,
}


@dataclass(frozen=True)
class AuthenticatedUser:
    username: str
    role: UserRole
    token_name: str


def _token_map() -> dict[str, AuthenticatedUser]:
    settings = get_settings()
    return {
        settings.viewer_api_token: AuthenticatedUser(
            username="viewer",
            role=UserRole.VIEWER,
            token_name="viewer_api_token",
        ),
        settings.analyst_api_token: AuthenticatedUser(
            username="analyst",
            role=UserRole.ANALYST,
            token_name="analyst_api_token",
        ),
        settings.admin_api_token: AuthenticatedUser(
            username="admin",
            role=UserRole.ADMIN,
            token_name="admin_api_token",
        ),
    }


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
) -> AuthenticatedUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = _token_map().get(credentials.credentials)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(min_role: UserRole) -> Callable[[AuthenticatedUser], AuthenticatedUser]:
    def dependency(current_user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if ROLE_ORDER[current_user.role] < ROLE_ORDER[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{min_role.value.capitalize()} role required",
            )
        return current_user

    return dependency
