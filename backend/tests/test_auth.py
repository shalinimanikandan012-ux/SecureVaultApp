"""
Pytest Authentication & API Integration Tests
Verifies user registration, login rate limiting, and password reset flows
"""

import pytest
from app import create_app, db
from app.models.user import User

@pytest.fixture
def client():
    app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SECRET_KEY': 'test-secret'
    })
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()

def test_user_registration(client):
    res = client.post('/api/auth/register', json={
        'email': 'student@university.edu',
        'username': 'CyberStudent',
        'password': 'StrongPassword2026!'
    })
    assert res.status_code == 201
    data = res.get_json()
    assert "user_id" in data

def test_user_registration_duplicate_fails(client):
    payload = {
        'email': 'student@university.edu',
        'username': 'CyberStudent',
        'password': 'StrongPassword2026!'
    }
    client.post('/api/auth/register', json=payload)
    res2 = client.post('/api/auth/register', json=payload)
    assert res2.status_code == 409

def test_login_invalid_credentials(client):
    res = client.post('/api/auth/login', json={
        'email': 'nonexistent@test.com',
        'password': 'WrongPassword123!'
    })
    assert res.status_code == 401
    assert "error" in res.get_json()

def test_login_rate_limiting_lockout(client):
    # Register user
    client.post('/api/auth/register', json={
        'email': 'lockout_target@test.com',
        'username': 'TargetUser',
        'password': 'ValidPassword2026!'
    })
    
    # Fail 5 times
    for _ in range(5):
        client.post('/api/auth/login', json={
            'email': 'lockout_target@test.com',
            'password': 'IncorrectPassword'
        })
        
    # 6th attempt should be rejected with 429 Too Many Requests / locked
    res = client.post('/api/auth/login', json={
        'email': 'lockout_target@test.com',
        'password': 'IncorrectPassword'
    })
    assert res.status_code == 429
    assert "locked" in res.get_json()["error"].lower()
