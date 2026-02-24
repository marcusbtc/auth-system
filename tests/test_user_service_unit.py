import pytest
from pymongo.errors import DuplicateKeyError

from app.core.errors import AppError
from app.models.user import UserRole
from app.services.user_service import UserService


class FakeAudit:
    def __init__(self):
        self.events = []

    def log(self, **kwargs):
        self.events.append(kwargs)


class FailingAudit:
    def log(self, **kwargs):
        raise RuntimeError('audit failed')


class FakeUsersRepo:
    def __init__(self):
        self.mode = 'ok'
        self.updated_payload = None

    def to_public(self, user):
        return {
            'id': str(user.get('_id', 'id-1')),
            'username': user.get('username', 'user'),
            'role': user.get('role', 'user'),
            'is_active': user.get('is_active', True),
            'created_at': user.get('created_at', 'now'),
            'updated_at': user.get('updated_at', 'now'),
            'last_login_at': user.get('last_login_at'),
        }

    def list_users(self, page, page_size, query, role, active):
        return ([{'_id': 'id-1', 'username': 'alice', 'role': 'user', 'is_active': True, 'created_at': 'now', 'updated_at': 'now'}], 1)

    def update_user(self, user_id, updates):
        self.updated_payload = updates
        if self.mode == 'duplicate':
            raise DuplicateKeyError('duplicate')
        if self.mode == 'invalid':
            raise ValueError('invalid id')
        if self.mode == 'missing':
            return None
        return {'_id': user_id, 'username': updates.get('username', 'alice'), 'role': updates.get('role', 'user'), 'is_active': True, 'created_at': 'now', 'updated_at': 'now'}

    def soft_delete_user(self, user_id):
        if self.mode == 'invalid':
            raise ValueError('invalid id')
        if self.mode == 'missing':
            return False
        return True


CURRENT_ADMIN = {'_id': 'admin-id', 'username': 'admin', 'role': 'admin'}
CURRENT_USER = {'_id': 'user-id', 'username': 'user', 'role': 'user'}


def test_get_me_and_list_users_normalization():
    service = UserService(users=FakeUsersRepo(), audit=FakeAudit())

    me = service.get_me(CURRENT_USER)
    assert me['user']['username'] == 'user'

    listing = service.list_users(page=0, page_size=500, query=None, role=UserRole.user, active=True)
    assert listing['page'] == 1
    assert listing['page_size'] == 100
    assert listing['total'] == 1


def test_update_user_forbidden_and_empty_update():
    service = UserService(users=FakeUsersRepo(), audit=FakeAudit())

    with pytest.raises(AppError) as exc:
        service.update_user('other-id', {'username': 'x'}, CURRENT_USER, ip_key='127.0.0.1')
    assert exc.value.code == 'FORBIDDEN'

    with pytest.raises(AppError) as exc:
        service.update_user('user-id', {}, CURRENT_USER, ip_key='127.0.0.1')
    assert exc.value.code == 'EMPTY_UPDATE'


def test_update_user_invalid_role_duplicate_invalid_id_missing_and_success():
    repo = FakeUsersRepo()
    service = UserService(users=repo, audit=FakeAudit())

    with pytest.raises(AppError) as exc:
        service.update_user('any-id', {'role': 'super-admin'}, CURRENT_ADMIN)
    assert exc.value.code == 'INVALID_ROLE'

    repo.mode = 'duplicate'
    with pytest.raises(AppError) as exc:
        service.update_user('any-id', {'username': 'taken'}, CURRENT_ADMIN)
    assert exc.value.code == 'USERNAME_EXISTS'

    repo.mode = 'invalid'
    with pytest.raises(AppError) as exc:
        service.update_user('any-id', {'username': 'alice'}, CURRENT_ADMIN)
    assert exc.value.code == 'INVALID_USER_ID'

    repo.mode = 'missing'
    with pytest.raises(AppError) as exc:
        service.update_user('any-id', {'username': 'alice'}, CURRENT_ADMIN)
    assert exc.value.code == 'USER_NOT_FOUND'

    repo.mode = 'ok'
    result = service.update_user('any-id', {'password': 'strongpass123', 'username': 'alice'}, CURRENT_ADMIN)
    assert result['message'] == 'User updated successfully'
    assert repo.updated_payload['username'] == 'alice'
    assert repo.updated_payload['password'].startswith('$2')


def test_delete_user_forbidden_invalid_missing_and_success():
    repo = FakeUsersRepo()
    service = UserService(users=repo, audit=FakeAudit())

    with pytest.raises(AppError) as exc:
        service.delete_user('any-id', CURRENT_USER)
    assert exc.value.code == 'FORBIDDEN'

    repo.mode = 'invalid'
    with pytest.raises(AppError) as exc:
        service.delete_user('any-id', CURRENT_ADMIN)
    assert exc.value.code == 'INVALID_USER_ID'

    repo.mode = 'missing'
    with pytest.raises(AppError) as exc:
        service.delete_user('any-id', CURRENT_ADMIN)
    assert exc.value.code == 'USER_NOT_FOUND'

    repo.mode = 'ok'
    result = service.delete_user('any-id', CURRENT_ADMIN)
    assert result['message'] == 'User deleted successfully'


def test_audit_failures_do_not_break_service_paths():
    service = UserService(users=FakeUsersRepo(), audit=FailingAudit())

    with pytest.raises(AppError) as exc:
        service.delete_user('any-id', CURRENT_USER)
    assert exc.value.code == 'FORBIDDEN'
