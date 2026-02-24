import logging
import time
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.deps import auth_service
from app.api.routes import auth, pages, system, users
from app.core.config import settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.metrics import metrics_store
from app.db.migrations import run_migrations
from app.db.mongo import db, ensure_indexes

configure_logging()
logger = logging.getLogger('auth-system')


@asynccontextmanager
async def lifespan(_: FastAPI):
    run_migrations(db)
    ensure_indexes()
    auth_service.seed_admin()
    yield


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)


@app.middleware('http')
async def request_context_middleware(request: Request, call_next):
    request_id = request.headers.get('x-request-id', str(uuid4()))
    started = time.perf_counter()
    response = await call_next(request)
    duration_ms = int((time.perf_counter() - started) * 1000)
    metrics_store.record(response.status_code, duration_ms)
    response.headers['x-request-id'] = request_id
    response.headers['x-response-time-ms'] = str(duration_ms)
    if settings.security_headers_enabled:
        response.headers['x-content-type-options'] = 'nosniff'
        response.headers['x-frame-options'] = 'DENY'
        response.headers['referrer-policy'] = 'same-origin'
        response.headers['content-security-policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
        response.headers['permissions-policy'] = 'camera=(), microphone=(), geolocation=()'
    logger.info(
        'request',
        extra={
            'request_id': request_id,
            'path': request.url.path,
            'method': request.method,
            'status_code': response.status_code,
        },
    )
    return response


register_exception_handlers(app)


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, __: Exception):
    return JSONResponse(status_code=500, content={'error': {'code': 'INTERNAL_ERROR', 'message': 'Internal server error'}})


app.include_router(system.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(pages.router)
