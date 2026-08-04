# Auth System FastAPI

Authentication backend with FastAPI, MongoDB, JWT access/refresh tokens, refresh rotation, token revocation, soft delete, rate limiting, CSRF, and a simple web UI.

## Stack

- FastAPI
- MongoDB (PyMongo)
- Redis (optional, for distributed rate limiting and token blacklist)
- JWT (`python-jose`)
- Password hashing (`passlib[bcrypt]`)
- Templates (`Jinja2`)
- Tests (`pytest`, `httpx`, `mongomock`)

## Setup

1. Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure environment variables:

```bash
cp .env.example .env
```

4. Set a strong `JWT_SECRET` (32+ characters) in `.env`.

5. Run the API:

```bash
uvicorn app.main:app --reload
```

API runs at `http://127.0.0.1:8000`.

## Architecture

- `app/core`: config, security, logging, metrics, error handling
- `app/db`: Mongo connection, indexes, migrations
- `app/repositories`: data access
- `app/services`: business rules
- `app/api/routes`: HTTP routes
- `app/models`: Pydantic schemas

## Endpoints

### Auth

- `POST /api/auth/register`
- `POST /api/auth/activate`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`

### Users

- `GET /api/users/me`
- `GET /api/users?page=1&page_size=10&q=&role=&is_active=`
- `PUT /api/users/{user_id}`
- `DELETE /api/users/{user_id}`
- `GET /api/users/admin`

### System

- `GET /api/system/health`
- `GET /api/system/ready`
- `GET /api/system/metrics`

### Pages

- `GET /`
- `GET /register-page`
- `GET /login-page`
- `GET /dashboard`

## Security Features

- bcrypt password hashing
- Short-lived access tokens + rotating refresh tokens
- Refresh token revocation on logout and rotation
- TTL index to auto-delete expired refresh tokens
- `HttpOnly` auth cookies
- Login/forgot-password rate limit (Redis with local fallback)
- Access-token blacklist on logout for immediate invalidation
- CSRF protection for state-changing cookie-authenticated requests
- Unique username index for active users
- Soft delete for users
- Standardized API error format
- Request ID and structured JSON logs
- Security audit trail in `audit_events` (login/refresh/logout/reset/update/delete)
- Configurable CORS and TrustedHost middleware
- Security headers (`CSP`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`)

## CSRF in Cookie Flow

After login, backend returns `csrf_token` in a cookie and in the response payload.
For cookie-authenticated `POST/PUT/PATCH/DELETE`, send:

`x-csrf-token: <csrf_token>`

## Production Notes

- `APP_ENV=production`
- `COOKIE_SECURE=true`
- `DEBUG_EXPOSE_TOKENS=false`
- `REDIS_URL` required
- Set `CORS_ALLOW_ORIGINS` and `TRUSTED_HOSTS` to real domains

## Migrations

Migrations run on startup and are tracked in `schema_migrations`.
File: `app/db/migrations.py`.

## Admin Seed

If `ADMIN_SEED_ENABLED=true`, startup creates:

- username: `ADMIN_SEED_USERNAME`
- password: `ADMIN_SEED_PASSWORD`
- role: `admin`

## Tests

```bash
pytest
```

Tests use `mongomock` and do not require a real Mongo instance.

## Quality

```bash
pip install -r requirements-dev.txt
ruff check app tests
mypy app
pytest
```

Coverage threshold: `79%`.
CI pipeline: `.github/workflows/ci.yml`.

## Docker

```bash
JWT_SECRET='<32+ character secret>' docker compose up --build --wait
```

API runs at `http://localhost:8000`.

MongoDB and Redis are private to the Compose network and persist in named
volumes. Before production deployment, set the domain-specific
`CORS_ALLOW_ORIGINS` and `TRUSTED_HOSTS` values, verify a Mongo backup, and
record the immutable application image tag used for rollback. See
[`docs/operations.md`](docs/operations.md).
