from app.db.mongo import audit_events_collection, refresh_tokens_collection


def test_refresh_token_has_ttl_index(client):
    indexes = refresh_tokens_collection.index_information()
    assert 'ttl_refresh_expires' in indexes
    ttl_index = indexes['ttl_refresh_expires']
    assert ttl_index.get('expireAfterSeconds') == 0


def test_audit_events_record_login_success_and_failure(client):
    client.post('/api/auth/login', json={'username': 'unknown', 'password': 'wrong'})
    failed = audit_events_collection.find_one({'event_type': 'auth.login', 'success': False})
    assert failed is not None

    register = client.post('/api/auth/register', json={'username': 'audited', 'password': 'strongpass123'})
    activation_token = register.json()['activation_token']
    client.post('/api/auth/activate', json={'token': activation_token})
    client.post('/api/auth/login', json={'username': 'audited', 'password': 'strongpass123'})

    success = audit_events_collection.find_one({'event_type': 'auth.login', 'success': True, 'actor_username': 'audited'})
    assert success is not None


def test_audit_events_record_admin_delete(client):
    register = client.post('/api/auth/register', json={'username': 'todelete', 'password': 'strongpass123'})
    client.post('/api/auth/activate', json={'token': register.json()['activation_token']})

    admin_login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'password'})
    access = admin_login.json()['access_token']
    csrf = admin_login.json()['csrf_token']

    me = client.get('/api/users?role=user', headers={'Authorization': f'Bearer {access}'})
    target = next(item for item in me.json()['items'] if item['username'] == 'todelete')

    deleted = client.delete(
        f"/api/users/{target['id']}",
        headers={'Authorization': f'Bearer {access}', 'x-csrf-token': csrf},
    )
    assert deleted.status_code == 200

    event = audit_events_collection.find_one({'event_type': 'user.delete', 'success': True, 'actor_username': 'admin'})
    assert event is not None
