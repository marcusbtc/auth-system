from pymongo import ASCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

from app.core.config import settings


def _build_client() -> MongoClient:
    if settings.mongo_uri.startswith('mongomock://'):
        import mongomock

        return mongomock.MongoClient()
    return MongoClient(settings.mongo_uri)


client: MongoClient = _build_client()
db: Database = client[settings.mongo_db]
users_collection: Collection = db['users']
refresh_tokens_collection: Collection = db['refresh_tokens']
audit_events_collection: Collection = db['audit_events']


def ensure_indexes() -> None:
    users_collection.create_index(
        [('username_normalized', ASCENDING)],
        unique=True,
        partialFilterExpression={'deleted_at': None},
        name='uq_username_active',
    )
    users_collection.create_index([('role', ASCENDING)], name='idx_role')
    users_collection.create_index([('is_active', ASCENDING)], name='idx_active')
    refresh_tokens_collection.create_index([('jti', ASCENDING)], unique=True, name='uq_refresh_jti')
    refresh_tokens_collection.create_index([('user_id', ASCENDING)], name='idx_refresh_user')
    for index_name in ('idx_refresh_expires', 'ttl_refresh_expires'):
        try:
            refresh_tokens_collection.drop_index(index_name)
        except Exception:
            pass
    refresh_tokens_collection.create_index(
        [('expires_at', ASCENDING)],
        expireAfterSeconds=0,
        name='ttl_refresh_expires',
    )
    audit_events_collection.create_index([('created_at', ASCENDING)], name='idx_audit_created_at')
    audit_events_collection.create_index([('event_type', ASCENDING)], name='idx_audit_event_type')
