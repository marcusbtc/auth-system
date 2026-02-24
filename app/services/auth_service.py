from typing import Any

from pymongo.errors import DuplicateKeyError

from app.core.config import settings
from app.core.errors import AppError
from app.core.security import (
    create_access_token,
    create_one_time_token,
    create_refresh_token,
    decode_token,
    hash_password,
    now_utc,
    seconds_until_exp,
    verify_password,
)
from app.core.security_store import SecurityStore
from app.models.user import UserRole
from app.repositories.token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService


class AuthService:
    def __init__(
        self,
        users: UserRepository,
        refresh_tokens: RefreshTokenRepository,
        store: SecurityStore,
        audit: AuditService,
    ):
        self.users = users
        self.refresh_tokens = refresh_tokens
        self.store = store
        self.audit = audit

    def _audit(self, event_type: str, success: bool, ip_key: str | None, actor: dict | None = None, metadata: dict | None = None) -> None:
        try:
            self.audit.log(event_type=event_type, success=success, ip_address=ip_key, actor=actor, metadata=metadata)
        except Exception:
            pass

    def register(self, username: str, password: str) -> dict[str, Any]:
        if self.users.username_exists(username):
            self._audit('auth.register', False, None, metadata={'username': username, 'reason': 'username_exists'})
            raise AppError('Username already exists', status_code=409, code='USERNAME_EXISTS')

        try:
            user = self.users.create_user(username=username, password_hash=hash_password(password), role=UserRole.user, active=False)
        except DuplicateKeyError as exc:
            self._audit('auth.register', False, None, metadata={'username': username, 'reason': 'duplicate_key'})
            raise AppError('Username already exists', status_code=409, code='USERNAME_EXISTS') from exc
        user_id = str(user['_id'])
        activation_token, activation_expires_at = create_one_time_token(
            ttl_minutes=settings.activation_token_expire_minutes,
            subject=user['username'],
            purpose='activate_account',
        )
        self.users.set_activation_token(user_id, activation_token, activation_expires_at)

        response = {'message': 'Registration successful. Check your email for activation instructions.'}
        if settings.debug_expose_tokens or settings.app_env in {'development', 'test'}:
            response['activation_token'] = activation_token
        self._audit('auth.register', True, None, actor=user, metadata={'username': username})
        return response

    def activate(self, token: str, ip_key: str | None = None) -> dict[str, Any]:
        payload = decode_token(token)
        if payload.get('type') != 'one_time' or payload.get('purpose') != 'activate_account':
            self._audit('auth.activate', False, ip_key, metadata={'reason': 'invalid_token'})
            raise AppError('Invalid activation token', status_code=400, code='INVALID_ACTIVATION_TOKEN')

        activated = self.users.activate_by_token(token, now_utc())
        if not activated:
            self._audit('auth.activate', False, ip_key, metadata={'reason': 'not_found_or_expired'})
            raise AppError('Activation token is invalid or expired', status_code=404, code='ACTIVATION_NOT_FOUND')
        user = self.users.find_by_username(payload.get('sub', ''))
        self._audit('auth.activate', True, ip_key, actor=user, metadata={'username': payload.get('sub')})
        return {'message': 'Account activated successfully'}

    def login(self, username: str, password: str, ip_key: str) -> dict[str, Any]:
        allowed = self.store.allow_rate_limit(
            key=f'login:{ip_key}',
            limit=settings.login_rate_limit_max_attempts,
            window_seconds=settings.login_rate_limit_window_seconds,
        )
        if not allowed:
            self._audit('auth.login', False, ip_key, metadata={'username': username, 'reason': 'rate_limited'})
            raise AppError('Too many login attempts. Try again later.', status_code=429, code='RATE_LIMITED')

        user = self.users.find_by_username(username)
        if not user or not verify_password(password, user['password']):
            self._audit('auth.login', False, ip_key, metadata={'username': username, 'reason': 'invalid_credentials'})
            raise AppError('Invalid credentials', status_code=401, code='INVALID_CREDENTIALS')
        if not user.get('is_active', True):
            self._audit('auth.login', False, ip_key, actor=user, metadata={'reason': 'account_inactive'})
            raise AppError('Account is not active', status_code=403, code='ACCOUNT_INACTIVE')

        access_token, _ = create_access_token(subject=user['username'], role=user['role'])
        refresh_token, refresh_jti, refresh_expires_at = create_refresh_token(subject=user['username'], role=user['role'])
        self.refresh_tokens.create(user_id=str(user['_id']), jti=refresh_jti, expires_at=refresh_expires_at)
        self.users.update_last_login(str(user['_id']))
        self._audit('auth.login', True, ip_key, actor=user)

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer',
            'expires_in': settings.access_token_expire_minutes * 60,
        }

    def refresh(self, refresh_token: str, ip_key: str | None = None) -> dict[str, Any]:
        payload = decode_token(refresh_token)
        if payload.get('type') != 'refresh' or 'jti' not in payload or 'sub' not in payload:
            self._audit('auth.refresh', False, ip_key, metadata={'reason': 'invalid_refresh_payload'})
            raise AppError('Invalid refresh token', status_code=401, code='INVALID_REFRESH_TOKEN')

        token_row = self.refresh_tokens.get_active(jti=payload['jti'], now=now_utc())
        if not token_row:
            self._audit('auth.refresh', False, ip_key, metadata={'reason': 'revoked_or_expired', 'username': payload.get('sub')})
            raise AppError('Refresh token revoked or expired', status_code=401, code='REFRESH_TOKEN_REVOKED')

        user = self.users.find_by_username(payload['sub'])
        if not user or user.get('deleted_at') is not None or not user.get('is_active', True):
            self.refresh_tokens.revoke(jti=payload['jti'])
            self._audit('auth.refresh', False, ip_key, metadata={'reason': 'invalid_user', 'username': payload.get('sub')})
            raise AppError('User no longer valid', status_code=401, code='INVALID_USER')

        new_access, _ = create_access_token(subject=user['username'], role=user['role'])
        new_refresh, new_jti, new_exp = create_refresh_token(subject=user['username'], role=user['role'])
        self.refresh_tokens.create(user_id=str(user['_id']), jti=new_jti, expires_at=new_exp)
        self.refresh_tokens.revoke(jti=payload['jti'], replaced_by_jti=new_jti)
        self._audit('auth.refresh', True, ip_key, actor=user)

        return {
            'access_token': new_access,
            'refresh_token': new_refresh,
            'token_type': 'bearer',
            'expires_in': settings.access_token_expire_minutes * 60,
        }

    def logout(self, refresh_token: str | None, access_token: str | None, ip_key: str | None = None) -> dict[str, Any]:
        actor = None
        if access_token:
            try:
                access_payload = decode_token(access_token)
                jti = access_payload.get('jti')
                actor = self.users.find_by_username(access_payload.get('sub', ''))
                if jti:
                    self.store.blacklist_token(jti, seconds_until_exp(access_payload))
            except AppError:
                pass
        if refresh_token:
            try:
                payload = decode_token(refresh_token)
                jti = payload.get('jti')
                if jti:
                    self.refresh_tokens.revoke(jti)
            except AppError:
                pass
        self._audit('auth.logout', True, ip_key, actor=actor)
        return {'message': 'Logged out successfully'}

    def forgot_password(self, username: str, ip_key: str) -> dict[str, Any]:
        allowed = self.store.allow_rate_limit(
            key=f'forgot:{ip_key}',
            limit=settings.forgot_rate_limit_max_attempts,
            window_seconds=settings.forgot_rate_limit_window_seconds,
        )
        if not allowed:
            self._audit('auth.forgot_password', False, ip_key, metadata={'username': username, 'reason': 'rate_limited'})
            raise AppError('Too many password reset requests. Try again later.', status_code=429, code='RATE_LIMITED')

        user = self.users.find_by_username(username)
        if not user:
            self._audit('auth.forgot_password', True, ip_key, metadata={'username': username, 'result': 'masked_not_found'})
            return {'message': 'If the account exists, reset instructions were sent.'}

        reset_token, reset_expires_at = create_one_time_token(
            ttl_minutes=settings.reset_token_expire_minutes,
            subject=user['username'],
            purpose='reset_password',
        )
        self.users.set_reset_token(str(user['_id']), reset_token, reset_expires_at)

        response: dict[str, Any] = {'message': 'If the account exists, reset instructions were sent.'}
        if settings.debug_expose_tokens:
            response['reset_token'] = reset_token
        self._audit('auth.forgot_password', True, ip_key, actor=user)
        return response

    def reset_password(self, token: str, new_password: str, ip_key: str | None = None) -> dict[str, Any]:
        payload = decode_token(token)
        if payload.get('type') != 'one_time' or payload.get('purpose') != 'reset_password':
            self._audit('auth.reset_password', False, ip_key, metadata={'reason': 'invalid_token'})
            raise AppError('Invalid reset token', status_code=400, code='INVALID_RESET_TOKEN')

        updated = self.users.reset_password_by_token(token=token, password_hash=hash_password(new_password), now=now_utc())
        if not updated:
            self._audit('auth.reset_password', False, ip_key, metadata={'reason': 'not_found_or_expired', 'username': payload.get('sub')})
            raise AppError('Reset token is invalid or expired', status_code=404, code='RESET_NOT_FOUND')
        actor = self.users.find_by_username(payload.get('sub', ''))
        self._audit('auth.reset_password', True, ip_key, actor=actor)
        return {'message': 'Password updated successfully'}

    def authenticate_access_token(self, token: str) -> dict[str, Any]:
        payload = decode_token(token)
        if payload.get('type') != 'access' or 'sub' not in payload:
            raise AppError('Invalid access token', status_code=401, code='INVALID_ACCESS_TOKEN')
        jti = payload.get('jti')
        if not jti or self.store.is_blacklisted(jti):
            raise AppError('Access token revoked', status_code=401, code='ACCESS_TOKEN_REVOKED')
        user = self.users.find_by_username(payload['sub'])
        if not user or user.get('deleted_at') is not None:
            raise AppError('User not found', status_code=401, code='USER_NOT_FOUND')
        if not user.get('is_active', True):
            raise AppError('User is inactive', status_code=403, code='USER_INACTIVE')
        return user

    def seed_admin(self) -> None:
        if not settings.admin_seed_enabled:
            return
        existing = self.users.find_by_username(settings.admin_seed_username)
        if existing:
            return
        try:
            self.users.create_user(
                username=settings.admin_seed_username,
                password_hash=hash_password(settings.admin_seed_password),
                role=UserRole.admin,
                active=True,
            )
        except DuplicateKeyError:
            return
