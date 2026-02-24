from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    app_name: str = 'Auth System FastAPI'
    app_version: str = '2.0.0'
    app_host: str = '0.0.0.0'
    app_port: int = 8000
    app_env: str = 'development'

    mongo_uri: str = 'mongodb://localhost:27017'
    mongo_db: str = 'auth_system'
    redis_url: str | None = None
    redis_prefix: str = 'authsys'

    jwt_secret: str = 'change-me-in-production'
    jwt_algorithm: str = 'HS256'
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    activation_token_expire_minutes: int = 60
    reset_token_expire_minutes: int = 30

    cookie_secure: bool = False
    cookie_samesite: Literal['lax', 'strict', 'none'] = 'lax'
    cookie_domain: str | None = None

    login_rate_limit_window_seconds: int = 60
    login_rate_limit_max_attempts: int = 5
    forgot_rate_limit_window_seconds: int = 300
    forgot_rate_limit_max_attempts: int = 3

    cors_allow_origins: list[str] = Field(default_factory=lambda: ['http://localhost:3000', 'http://127.0.0.1:3000'])
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = Field(default_factory=lambda: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    cors_allow_headers: list[str] = Field(default_factory=lambda: ['Authorization', 'Content-Type', 'X-CSRF-Token', 'X-Request-ID'])
    trusted_hosts: list[str] = Field(default_factory=lambda: ['localhost', '127.0.0.1', '*.localhost', 'testserver'])

    security_headers_enabled: bool = True

    admin_seed_username: str = 'admin'
    admin_seed_password: str = 'password'
    admin_seed_enabled: bool = True

    debug_expose_tokens: bool = False

    @field_validator('jwt_secret')
    @classmethod
    def validate_jwt_secret(cls, value: str) -> str:
        if value == 'change-me-in-production' or len(value) < 32:
            raise ValueError('JWT_SECRET must be set and have at least 32 characters')
        return value

    @field_validator('app_env')
    @classmethod
    def validate_app_env(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {'development', 'staging', 'production', 'test'}:
            raise ValueError('APP_ENV must be development, staging, production or test')
        return normalized

    @property
    def is_production(self) -> bool:
        return self.app_env == 'production'

    def validate_runtime(self) -> None:
        if self.is_production and not self.cookie_secure:
            raise ValueError('COOKIE_SECURE must be true in production')
        if self.is_production and self.debug_expose_tokens:
            raise ValueError('DEBUG_EXPOSE_TOKENS must be false in production')
        if self.is_production and not self.redis_url:
            raise ValueError('REDIS_URL is required in production')


settings = Settings()
settings.validate_runtime()
