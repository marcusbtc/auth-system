from app.db.mongo import users_collection


def test_forgot_and_reset_password_flow(client):
    reg = client.post('/api/auth/register', json={'username': 'recover', 'password': 'strongpass123'})
    activation_token = reg.json()['activation_token']
    client.post('/api/auth/activate', json={'token': activation_token})

    forgot = client.post('/api/auth/forgot-password', json={'username': 'recover'})
    assert forgot.status_code == 200
    reset_token = forgot.json().get('reset_token')
    assert reset_token

    reset = client.post('/api/auth/reset-password', json={'token': reset_token, 'new_password': 'newstrongpass123'})
    assert reset.status_code == 200

    old_login = client.post('/api/auth/login', json={'username': 'recover', 'password': 'strongpass123'})
    assert old_login.status_code == 401

    new_login = client.post('/api/auth/login', json={'username': 'recover', 'password': 'newstrongpass123'})
    assert new_login.status_code == 200


def test_users_pagination_and_filter(client):
    admin_login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'password'})
    admin_access = admin_login.json()['access_token']

    for i in range(12):
        reg = client.post('/api/auth/register', json={'username': f'user{i}', 'password': 'strongpass123'})
        client.post('/api/auth/activate', json={'token': reg.json()['activation_token']})

    first_page = client.get('/api/users?page=1&page_size=5', headers={'Authorization': f'Bearer {admin_access}'})
    assert first_page.status_code == 200
    assert first_page.json()['page'] == 1
    assert first_page.json()['page_size'] == 5
    assert first_page.json()['total'] >= 12
    assert len(first_page.json()['items']) == 5

    filtered = client.get('/api/users?q=user1', headers={'Authorization': f'Bearer {admin_access}'})
    assert filtered.status_code == 200
    assert any('user1' in item['username'] for item in filtered.json()['items'])

    target = users_collection.find_one({'username_normalized': 'user0'})
    delete = client.delete(f"/api/users/{str(target['_id'])}", headers={'Authorization': f'Bearer {admin_access}'})
    assert delete.status_code == 200

    after_delete = users_collection.find_one({'_id': target['_id']})
    assert after_delete['deleted_at'] is not None
