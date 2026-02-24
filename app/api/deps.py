from fastapi import Cookie, Depends, Header, Request

from app.core.errors import AppError
from app.core.security_store import SecurityStore
from app.repositories.audit_repository import AuditRepository
from app.repositories.token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.user_service import UserService

users_repo = UserRepository()
refresh_repo = RefreshTokenRepository()
audit_repo = AuditRepository()
audit_service = AuditService(repo=audit_repo)
security_store = SecurityStore()
auth_service = AuthService(users=users_repo, refresh_tokens=refresh_repo, store=security_store, audit=audit_service)
user_service = UserService(users=users_repo, audit=audit_service)


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get('x-forwarded-for')
    if forwarded:
        return forwarded.split(',')[0].strip()
    if request.client:
        return request.client.host
    return 'unknown'


def get_bearer_token(authorization: str | None = Header(default=None)) -> str | None:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    return parts[1]


def get_current_user(
    bearer_token: str | None = Depends(get_bearer_token),
    access_cookie: str | None = Cookie(default=None, alias='access_token'),
):
    token = bearer_token or access_cookie
    if not token:
        raise AppError('Authentication required', status_code=401, code='UNAUTHORIZED')
    return auth_service.authenticate_access_token(token)


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get('role') != 'admin':
        raise AppError('Admin only route', status_code=403, code='FORBIDDEN')
    return current_user


def enforce_csrf(
    request: Request,
    authorization: str | None = Header(default=None),
    access_cookie: str | None = Cookie(default=None, alias='access_token'),
    csrf_cookie: str | None = Cookie(default=None, alias='csrf_token'),
    csrf_header: str | None = Header(default=None, alias='x-csrf-token'),
) -> None:
    if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return
    if authorization:
        return
    if not access_cookie:
        return
    if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
        raise AppError('Invalid CSRF token', status_code=403, code='CSRF_VALIDATION_FAILED')
