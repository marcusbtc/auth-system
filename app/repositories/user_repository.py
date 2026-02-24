from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from pymongo.collection import Collection

from app.db.mongo import users_collection
from app.models.user import UserRole


def _utcnow() -> datetime:
    return datetime.now(UTC)


def normalize_username(username: str) -> str:
    return username.strip().lower()


class UserRepository:
    def __init__(self, collection: Collection = users_collection):
        self.collection = collection

    def to_public(self, user: dict[str, Any]) -> dict[str, Any]:
        return {
            'id': str(user['_id']),
            'username': user['username'],
            'role': user.get('role', UserRole.user.value),
            'is_active': user.get('is_active', True),
            'created_at': user['created_at'],
            'updated_at': user['updated_at'],
            'last_login_at': user.get('last_login_at'),
        }

    def create_user(self, username: str, password_hash: str, role: UserRole = UserRole.user, active: bool = False) -> dict[str, Any]:
        now = _utcnow()
        doc = {
            'username': username,
            'username_normalized': normalize_username(username),
            'password': password_hash,
            'role': role.value,
            'is_active': active,
            'activation_token': None,
            'activation_expires_at': None,
            'reset_token': None,
            'reset_expires_at': None,
            'created_at': now,
            'updated_at': now,
            'last_login_at': None,
            'deleted_at': None,
        }
        inserted = self.collection.insert_one(doc)
        created_user = self.collection.find_one({'_id': inserted.inserted_id})
        if created_user is None:
            raise RuntimeError('Failed to create user')
        return created_user

    def find_by_username(self, username: str) -> dict[str, Any] | None:
        return self.collection.find_one({'username_normalized': normalize_username(username), 'deleted_at': None})

    def find_by_id(self, user_id: str) -> dict[str, Any] | None:
        try:
            object_id = ObjectId(user_id)
        except Exception:
            return None
        return self.collection.find_one({'_id': object_id, 'deleted_at': None})

    def set_activation_token(self, user_id: str, token: str, expires_at: datetime) -> None:
        self.collection.update_one(
            {'_id': ObjectId(user_id), 'deleted_at': None},
            {'$set': {'activation_token': token, 'activation_expires_at': expires_at, 'updated_at': _utcnow()}},
        )

    def activate_by_token(self, token: str, now: datetime) -> bool:
        result = self.collection.update_one(
            {'activation_token': token, 'activation_expires_at': {'$gt': now}, 'deleted_at': None},
            {
                '$set': {'is_active': True, 'activation_token': None, 'activation_expires_at': None, 'updated_at': _utcnow()},
            },
        )
        return result.matched_count > 0

    def set_reset_token(self, user_id: str, token: str, expires_at: datetime) -> None:
        self.collection.update_one(
            {'_id': ObjectId(user_id), 'deleted_at': None},
            {'$set': {'reset_token': token, 'reset_expires_at': expires_at, 'updated_at': _utcnow()}},
        )

    def reset_password_by_token(self, token: str, password_hash: str, now: datetime) -> bool:
        result = self.collection.update_one(
            {'reset_token': token, 'reset_expires_at': {'$gt': now}, 'deleted_at': None},
            {
                '$set': {
                    'password': password_hash,
                    'reset_token': None,
                    'reset_expires_at': None,
                    'updated_at': _utcnow(),
                }
            },
        )
        return result.matched_count > 0

    def update_last_login(self, user_id: str) -> None:
        self.collection.update_one({'_id': ObjectId(user_id)}, {'$set': {'last_login_at': _utcnow(), 'updated_at': _utcnow()}})

    def update_user(self, user_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        if 'username' in fields:
            fields['username_normalized'] = normalize_username(fields['username'])
        fields['updated_at'] = _utcnow()
        result = self.collection.update_one({'_id': ObjectId(user_id), 'deleted_at': None}, {'$set': fields})
        if result.matched_count == 0:
            return None
        return self.collection.find_one({'_id': ObjectId(user_id), 'deleted_at': None})

    def soft_delete_user(self, user_id: str) -> bool:
        result = self.collection.update_one(
            {'_id': ObjectId(user_id), 'deleted_at': None},
            {'$set': {'deleted_at': _utcnow(), 'is_active': False, 'updated_at': _utcnow()}},
        )
        return result.matched_count > 0

    def list_users(self, page: int, page_size: int, query: str | None, role: str | None, active: bool | None) -> tuple[list[dict[str, Any]], int]:
        filters: dict[str, Any] = {'deleted_at': None}
        if query:
            filters['username_normalized'] = {'$regex': query.strip().lower()}
        if role:
            filters['role'] = role
        if active is not None:
            filters['is_active'] = active
        total = self.collection.count_documents(filters)
        skip = (page - 1) * page_size
        cursor = self.collection.find(filters).sort('created_at', -1).skip(skip).limit(page_size)
        return list(cursor), total

    def username_exists(self, username: str) -> bool:
        return self.collection.count_documents({'username_normalized': normalize_username(username), 'deleted_at': None}) > 0
