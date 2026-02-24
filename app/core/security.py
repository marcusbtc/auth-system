import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.core.errors import AppError

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def now_utc() -> datetime:
    return datetime.now(UTC)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _create_token(subject: str, role: str, token_type: str, ttl: timedelta, jti: str) -> str:
    payload = {
        'sub': subject,
        'role': role,
        'type': token_type,
        'jti': jti,
        'iat': now_utc(),
        'exp': now_utc() + ttl,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_access_token(subject: str, role: str) -> tuple[str, str]:
    jti = str(uuid4())
    token = _create_token(
        subject=subject,
        role=role,
        token_type='access',
        ttl=timedelta(minutes=settings.access_token_expire_minutes),
        jti=jti,
    )
    return token, jti


def create_refresh_token(subject: str, role: str) -> tuple[str, str, datetime]:
    jti = str(uuid4())
    expires_at = now_utc() + timedelta(days=settings.refresh_token_expire_days)
    token = _create_token(
        subject=subject,
        role=role,
        token_type='refresh',
        ttl=timedelta(days=settings.refresh_token_expire_days),
        jti=jti,
    )
    return token, jti, expires_at


def create_one_time_token(ttl_minutes: int, subject: str, purpose: str) -> tuple[str, datetime]:
    expires_at = now_utc() + timedelta(minutes=ttl_minutes)
    payload = {
        'sub': subject,
        'purpose': purpose,
        'type': 'one_time',
        'iat': now_utc(),
        'exp': expires_at,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, expires_at


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise AppError('Invalid or expired token', status_code=401, code='INVALID_TOKEN') from exc


def seconds_until_exp(payload: dict) -> int:
    exp = payload.get('exp')
    if isinstance(exp, datetime):
        return max(0, int((exp - now_utc()).total_seconds()))
    if isinstance(exp, int | float):
        return max(0, int(exp - now_utc().timestamp()))
    return 0


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)
