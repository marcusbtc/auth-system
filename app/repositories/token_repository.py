from datetime import UTC, datetime

from bson import ObjectId
from pymongo.collection import Collection

from app.db.mongo import refresh_tokens_collection


def _utcnow() -> datetime:
    return datetime.now(UTC)


class RefreshTokenRepository:
    def __init__(self, collection: Collection = refresh_tokens_collection):
        self.collection = collection

    def create(self, user_id: str, jti: str, expires_at: datetime) -> None:
        self.collection.insert_one(
            {
                'user_id': ObjectId(user_id),
                'jti': jti,
                'expires_at': expires_at,
                'created_at': _utcnow(),
                'revoked_at': None,
                'replaced_by_jti': None,
            }
        )

    def get_active(self, jti: str, now: datetime) -> dict | None:
        return self.collection.find_one({'jti': jti, 'revoked_at': None, 'expires_at': {'$gt': now}})

    def revoke(self, jti: str, replaced_by_jti: str | None = None) -> None:
        self.collection.update_one(
            {'jti': jti, 'revoked_at': None},
            {'$set': {'revoked_at': _utcnow(), 'replaced_by_jti': replaced_by_jti}},
        )

    def revoke_user_tokens(self, user_id: str) -> None:
        self.collection.update_many({'user_id': ObjectId(user_id), 'revoked_at': None}, {'$set': {'revoked_at': _utcnow()}})
