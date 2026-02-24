from typing import Any

from app.repositories.audit_repository import AuditRepository


class AuditService:
    def __init__(self, repo: AuditRepository):
        self.repo = repo

    def log(self, event_type: str, success: bool, ip_address: str | None, actor: dict | None = None, metadata: dict[str, Any] | None = None) -> None:
        actor_user_id = None
        actor_username = None
        if actor is not None:
            actor_user_id = str(actor.get('_id')) if actor.get('_id') else None
            actor_username = actor.get('username')
        self.repo.log_event(
            event_type=event_type,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            success=success,
            ip_address=ip_address,
            metadata=metadata,
        )
