from datetime import UTC, datetime
from typing import Any

from app.db.mongo import audit_events_collection


class AuditRepository:
    def __init__(self):
        self.collection = audit_events_collection

    def log_event(
        self,
        event_type: str,
        actor_user_id: str | None,
        actor_username: str | None,
        success: bool,
        ip_address: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.collection.insert_one(
            {
                'event_type': event_type,
                'actor_user_id': actor_user_id,
                'actor_username': actor_username,
                'success': success,
                'ip_address': ip_address,
                'metadata': metadata or {},
                'created_at': datetime.now(UTC),
            }
        )
