from datetime import UTC, datetime

from fastapi import APIRouter

from app.api.deps import security_store
from app.core.config import settings
from app.core.metrics import metrics_store
from app.db.mongo import db

router = APIRouter(prefix='/api/system', tags=['system'])


@router.get('/health')
def health():
    return {'status': 'ok', 'timestamp': datetime.now(UTC).isoformat()}


@router.get('/ready')
def ready():
    db.command('ping')
    return {'status': 'ready'}


@router.get('/metrics')
def metrics():
    return {
        'app_env': settings.app_env,
        'redis_enabled': security_store.redis_enabled,
        'metrics': metrics_store.snapshot(),
    }
