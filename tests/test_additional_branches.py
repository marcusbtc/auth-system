from bson import ObjectId

from app.db.mongo import users_collection


def _register_activate(client, username: str, password: str = 'strongpass123'):
    reg = client.post('/api/auth/register', json={'username': username, 'password': password})
    assert reg.status_code == 200
    activation_token = reg.json()['activation_token']
    activated = client.post('/api/auth/activate', json={'token': activation_token})
    assert activated.status_code == 200


def _login(client, username: str, password: str = 'strongpass123'):
    login = client.post('/api/auth/login', json={'username': username, 'password': password})
    assert login.status_code == 200
    return login.json()


def test_pages_and_system_routes(client):
    assert client.get('/').status_code == 200
    assert client.get('/login-page').status_code == 200
    assert client.get('/register-page').status_code == 200

    health = client.get('/api/system/health')
    assert health.status_code == 200
    assert health.json()['status'] == 'ok'

    ready = client.get('/api/system/ready')
    assert ready.status_code == 200
    assert ready.json()['status'] == 'ready'

    metrics = client.get('/api/system/metrics')
    assert metrics.status_code == 200
    assert 'metrics' in metrics.json()


def test_activate_invalid_purpose_and_expired(client):
    _register_activate(client, 'purpose_user')

    forgot = client.post('/api/auth/forgot-password', json={'username': 'purpose_user'})
    reset_token = forgot.json()['reset_token']
    wrong_purpose = client.post('/api/auth/activate', json={'token': reset_token})
    assert wrong_purpose.status_code == 400

    reg = client.post('/api/auth/register', json={'username': 'double_activate', 'password': 'strongpass123'})
    token = reg.json()['activation_token']
    first = client.post('/api/auth/activate', json={'token': token})
    assert first.status_code == 200
    second = client.post('/api/auth/activate', json={'token': token})
    assert second.status_code == 404


def test_refresh_invalid_payload_and_invalid_user(client):
    _register_activate(client, 'refresh_invalid')
    tokens = _login(client, 'refresh_invalid')

    client.cookies.set('refresh_token', tokens['access_token'])
    client.cookies.set('csrf_token', tokens['csrf_token'])
    invalid_payload = client.post('/api/auth/refresh', headers={'x-csrf-token': tokens['csrf_token']})
    assert invalid_payload.status_code == 401

    user_doc = users_collection.find_one({'username_normalized': 'refresh_invalid'})
    users_collection.update_one({'_id': user_doc['_id']}, {'$set': {'deleted_at': 'now'}})

    client.cookies.set('refresh_token', tokens['refresh_token'])
    invalid_user = client.post('/api/auth/refresh', headers={'x-csrf-token': tokens['csrf_token']})
    assert invalid_user.status_code == 401


def test_logout_with_invalid_tokens_does_not_break(client):
    response = client.post('/api/auth/logout', headers={'Authorization': 'Bearer invalid.token.value'})
    assert response.status_code == 200


def test_forgot_password_not_found_and_rate_limit(client):
    masked = client.post('/api/auth/forgot-password', json={'username': 'missing_user'})
    assert masked.status_code == 200
    assert 'If the account exists' in masked.json()['message']

    for _ in range(2):
        ok = client.post('/api/auth/forgot-password', json={'username': 'missing_user'})
        assert ok.status_code == 200

    limited = client.post('/api/auth/forgot-password', json={'username': 'missing_user'})
    assert limited.status_code == 429


def test_reset_password_invalid_token_and_reuse(client):
    _register_activate(client, 'reset_user')

    reg = client.post('/api/auth/register', json={'username': 'activation_source', 'password': 'strongpass123'})
    activation_token = reg.json()['activation_token']
    wrong = client.post('/api/auth/reset-password', json={'token': activation_token, 'new_password': 'newstrongpass123'})
    assert wrong.status_code == 400

    forgot = client.post('/api/auth/forgot-password', json={'username': 'reset_user'})
    reset_token = forgot.json()['reset_token']
    first = client.post('/api/auth/reset-password', json={'token': reset_token, 'new_password': 'newstrongpass123'})
    assert first.status_code == 200
    second = client.post('/api/auth/reset-password', json={'token': reset_token, 'new_password': 'anotherpass123'})
    assert second.status_code == 404


def test_user_update_and_delete_error_branches(client):
    _register_activate(client, 'usr1')
    _register_activate(client, 'usr2')

    user1_tokens = _login(client, 'usr1')
    admin_tokens = _login(client, 'admin', 'password')

    user2_doc = users_collection.find_one({'username_normalized': 'usr2'})
    user1_doc = users_collection.find_one({'username_normalized': 'usr1'})

    forbidden_update = client.put(
        f"/api/users/{str(user2_doc['_id'])}",
        json={'username': 'u2_new'},
        headers={'Authorization': f"Bearer {user1_tokens['access_token']}"},
    )
    assert forbidden_update.status_code == 403

    empty_update = client.put(
        f"/api/users/{str(user1_doc['_id'])}",
        json={},
        headers={'Authorization': f"Bearer {user1_tokens['access_token']}"},
    )
    assert empty_update.status_code == 400

    duplicate_username = client.put(
        f"/api/users/{str(user2_doc['_id'])}",
        json={'username': 'usr1'},
        headers={'Authorization': f"Bearer {admin_tokens['access_token']}"},
    )
    assert duplicate_username.status_code == 409

    invalid_id_update = client.put(
        '/api/users/not-an-object-id',
        json={'username': 'new_name'},
        headers={'Authorization': f"Bearer {admin_tokens['access_token']}"},
    )
    assert invalid_id_update.status_code == 400

    missing_id = str(ObjectId())
    missing_update = client.put(
        f'/api/users/{missing_id}',
        json={'username': 'new_name'},
        headers={'Authorization': f"Bearer {admin_tokens['access_token']}"},
    )
    assert missing_update.status_code == 404

    forbidden_delete = client.delete(
        f"/api/users/{str(user2_doc['_id'])}",
        headers={'Authorization': f"Bearer {user1_tokens['access_token']}"},
    )
    assert forbidden_delete.status_code == 403

    invalid_delete = client.delete(
        '/api/users/not-an-object-id',
        headers={'Authorization': f"Bearer {admin_tokens['access_token']}"},
    )
    assert invalid_delete.status_code == 400

    missing_delete = client.delete(
        f'/api/users/{str(ObjectId())}',
        headers={'Authorization': f"Bearer {admin_tokens['access_token']}"},
    )
    assert missing_delete.status_code == 404
