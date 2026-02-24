from pymongo.errors import DuplicateKeyError

from app.core.errors import AppError
from app.core.security import hash_password
from app.models.user import UserRole
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService


class UserService:
    def __init__(self, users: UserRepository, audit: AuditService):
        self.users = users
        self.audit = audit

    def _audit(self, event_type: str, success: bool, ip_key: str | None, actor: dict | None = None, metadata: dict | None = None) -> None:
        try:
            self.audit.log(event_type=event_type, success=success, ip_address=ip_key, actor=actor, metadata=metadata)
        except Exception:
            pass

    def get_me(self, current_user: dict) -> dict:
        return {'user': self.users.to_public(current_user)}

    def list_users(self, page: int, page_size: int, query: str | None, role: UserRole | None, active: bool | None) -> dict:
        page = max(1, page)
        page_size = max(1, min(100, page_size))
        role_value = role.value if role else None
        docs, total = self.users.list_users(page=page, page_size=page_size, query=query, role=role_value, active=active)
        return {
            'items': [self.users.to_public(user) for user in docs],
            'page': page,
            'page_size': page_size,
            'total': total,
        }

    def update_user(self, target_user_id: str, payload: dict, current_user: dict, ip_key: str | None = None) -> dict:
        current_user_id = str(current_user['_id'])
        is_admin = current_user.get('role') == UserRole.admin.value
        if not is_admin and target_user_id != current_user_id:
            self._audit('user.update', False, ip_key, actor=current_user, metadata={'target_user_id': target_user_id, 'reason': 'forbidden'})
            raise AppError('Not allowed to update this user', status_code=403, code='FORBIDDEN')

        allowed_fields = {'username', 'password'}
        if is_admin:
            allowed_fields |= {'role', 'is_active'}

        updates = {k: v for k, v in payload.items() if v is not None and k in allowed_fields}
        if not updates:
            self._audit('user.update', False, ip_key, actor=current_user, metadata={'target_user_id': target_user_id, 'reason': 'empty_update'})
            raise AppError('No fields to update', status_code=400, code='EMPTY_UPDATE')

        if 'password' in updates:
            updates['password'] = hash_password(updates['password'])
        if 'role' in updates and updates['role'] not in {UserRole.user.value, UserRole.admin.value}:
            self._audit('user.update', False, ip_key, actor=current_user, metadata={'target_user_id': target_user_id, 'reason': 'invalid_role'})
            raise AppError('Invalid role', status_code=400, code='INVALID_ROLE')

        try:
            user = self.users.update_user(target_user_id, updates)
        except DuplicateKeyError as exc:
            self._audit('user.update', False, ip_key, actor=current_user, metadata={'target_user_id': target_user_id, 'reason': 'username_exists'})
            raise AppError('Username already exists', status_code=409, code='USERNAME_EXISTS') from exc
        except Exception as exc:
            self._audit('user.update', False, ip_key, actor=current_user, metadata={'target_user_id': target_user_id, 'reason': 'invalid_user_id'})
            raise AppError('Invalid user id', status_code=400, code='INVALID_USER_ID') from exc

        if not user:
            self._audit('user.update', False, ip_key, actor=current_user, metadata={'target_user_id': target_user_id, 'reason': 'user_not_found'})
            raise AppError('User not found', status_code=404, code='USER_NOT_FOUND')
        self._audit('user.update', True, ip_key, actor=current_user, metadata={'target_user_id': target_user_id, 'fields': list(updates.keys())})
        return {'message': 'User updated successfully', 'user': self.users.to_public(user)}

    def delete_user(self, target_user_id: str, current_user: dict, ip_key: str | None = None) -> dict:
        if current_user.get('role') != UserRole.admin.value:
            self._audit('user.delete', False, ip_key, actor=current_user, metadata={'target_user_id': target_user_id, 'reason': 'forbidden'})
            raise AppError('Admin only route', status_code=403, code='FORBIDDEN')
        try:
            deleted = self.users.soft_delete_user(target_user_id)
        except Exception as exc:
            self._audit('user.delete', False, ip_key, actor=current_user, metadata={'target_user_id': target_user_id, 'reason': 'invalid_user_id'})
            raise AppError('Invalid user id', status_code=400, code='INVALID_USER_ID') from exc

        if not deleted:
            self._audit('user.delete', False, ip_key, actor=current_user, metadata={'target_user_id': target_user_id, 'reason': 'user_not_found'})
            raise AppError('User not found', status_code=404, code='USER_NOT_FOUND')
        self._audit('user.delete', True, ip_key, actor=current_user, metadata={'target_user_id': target_user_id})
        return {'message': 'User deleted successfully'}
