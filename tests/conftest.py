import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ['MONGO_URI'] = 'mongomock://localhost'
os.environ['MONGO_DB'] = 'auth_system_test'
os.environ['JWT_SECRET'] = 'test-secret-with-at-least-32-characters-123'
os.environ['DEBUG_EXPOSE_TOKENS'] = 'true'
os.environ['ADMIN_SEED_ENABLED'] = 'true'
os.environ['ADMIN_SEED_USERNAME'] = 'admin'
os.environ['ADMIN_SEED_PASSWORD'] = 'password'
os.environ['COOKIE_SECURE'] = 'false'
os.environ['COOKIE_SAMESITE'] = 'lax'

import pytest
from fastapi.testclient import TestClient

from app.api.deps import auth_service
from app.db.mongo import audit_events_collection, refresh_tokens_collection, users_collection
from app.main import app


@pytest.fixture(autouse=True)
def clean_db():
    users_collection.delete_many({})
    refresh_tokens_collection.delete_many({})
    audit_events_collection.delete_many({})
    auth_service.store.reset_local_state()
    yield
    users_collection.delete_many({})
    refresh_tokens_collection.delete_many({})
    audit_events_collection.delete_many({})
    auth_service.store.reset_local_state()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
