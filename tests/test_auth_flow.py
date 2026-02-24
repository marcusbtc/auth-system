from app.db.mongo import users_collection


def test_register_activate_login_and_access_protected_route(client):
    register = client.post('/api/auth/register', json={'username': 'john', 'password': 'strongpass123'})
    assert register.status_code == 200
    activation_token = register.json().get('activation_token')
    assert activation_token

    activate = client.post('/api/auth/activate', json={'token': activation_token})
    assert activate.status_code == 200

    login = client.post('/api/auth/login', json={'username': 'john', 'password': 'strongpass123'})
    assert login.status_code == 200
    payload = login.json()
    assert payload['access_token']
    assert payload['refresh_token']

    me = client.get('/api/users/me', headers={'Authorization': f"Bearer {payload['access_token']}"})
    assert me.status_code == 200
    assert me.json()['user']['username'] == 'john'


def test_refresh_rotation_revokes_old_refresh_token(client):
    register = client.post('/api/auth/register', json={'username': 'refreshuser', 'password': 'strongpass123'})
    activation_token = register.json()['activation_token']
    client.post('/api/auth/activate', json={'token': activation_token})

    login = client.post('/api/auth/login', json={'username': 'refreshuser', 'password': 'strongpass123'})
    old_refresh = login.json()['refresh_token']
    csrf_token = login.json()['csrf_token']

    client.cookies.set('refresh_token', old_refresh)
    client.cookies.set('csrf_token', csrf_token)
    refreshed = client.post('/api/auth/refresh', headers={'x-csrf-token': csrf_token})
    assert refreshed.status_code == 200
    new_refresh = refreshed.json()['refresh_token']
    new_csrf = refreshed.json()['csrf_token']
    assert new_refresh != old_refresh

    client.cookies.set('refresh_token', old_refresh)
    client.cookies.set('csrf_token', new_csrf)
    second_try = client.post('/api/auth/refresh', headers={'x-csrf-token': new_csrf})
    assert second_try.status_code == 401


def test_refresh_requires_csrf_for_cookie_auth(client):
    reg = client.post('/api/auth/register', json={'username': 'csrfuser', 'password': 'strongpass123'})
    client.post('/api/auth/activate', json={'token': reg.json()['activation_token']})
    login = client.post('/api/auth/login', json={'username': 'csrfuser', 'password': 'strongpass123'})
    refresh = login.json()['refresh_token']
    client.cookies.set('refresh_token', refresh)
    blocked = client.post('/api/auth/refresh')
    assert blocked.status_code == 403


def test_logout_revokes_access_token_immediately(client):
    reg = client.post('/api/auth/register', json={'username': 'logoutuser', 'password': 'strongpass123'})
    client.post('/api/auth/activate', json={'token': reg.json()['activation_token']})
    login = client.post('/api/auth/login', json={'username': 'logoutuser', 'password': 'strongpass123'})
    access = login.json()['access_token']
    csrf = login.json()['csrf_token']

    before = client.get('/api/users/me', headers={'Authorization': f'Bearer {access}'})
    assert before.status_code == 200

    logout = client.post('/api/auth/logout', headers={'Authorization': f'Bearer {access}', 'x-csrf-token': csrf})
    assert logout.status_code == 200

    after = client.get('/api/users/me', headers={'Authorization': f'Bearer {access}'})
    assert after.status_code == 401


def test_admin_route_requires_admin(client):
    register = client.post('/api/auth/register', json={'username': 'basic', 'password': 'strongpass123'})
    client.post('/api/auth/activate', json={'token': register.json()['activation_token']})
    login = client.post('/api/auth/login', json={'username': 'basic', 'password': 'strongpass123'})
    access = login.json()['access_token']

    forbidden = client.get('/api/users/admin', headers={'Authorization': f'Bearer {access}'})
    assert forbidden.status_code == 403


def test_admin_seed_can_access_admin_route(client):
    login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'password'})
    assert login.status_code == 200
    access = login.json()['access_token']

    allowed = client.get('/api/users/admin', headers={'Authorization': f'Bearer {access}'})
    assert allowed.status_code == 200


def test_soft_delete_user(client):
    register = client.post('/api/auth/register', json={'username': 'deletable', 'password': 'strongpass123'})
    client.post('/api/auth/activate', json={'token': register.json()['activation_token']})
    user_doc = users_collection.find_one({'username_normalized': 'deletable'})

    admin_login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'password'})
    admin_access = admin_login.json()['access_token']
    deleted = client.delete(f"/api/users/{str(user_doc['_id'])}", headers={'Authorization': f'Bearer {admin_access}'})
    assert deleted.status_code == 200

    user_after = users_collection.find_one({'_id': user_doc['_id']})
    assert user_after['deleted_at'] is not None


def test_login_rate_limit(client):
    for _ in range(5):
        wrong = client.post('/api/auth/login', json={'username': 'nope', 'password': 'bad'})
        assert wrong.status_code == 401

    limited = client.post('/api/auth/login', json={'username': 'nope', 'password': 'bad'})
    assert limited.status_code == 429
