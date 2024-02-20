import base64
import pytest
from run import app as flask_app  # Import your Flask app here
import json

@pytest.fixture
def app():
    yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()

def test_registration(client):
    """Test user registration"""
    response = client.post('/register', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 201
    assert b'User registered successfully' in response.data

def test_login(client):
    """Test user login and token receipt using HTTP Basic Authentication"""
    username = 'testuser'
    password = 'testpassword'
    credentials = base64.b64encode(f'{username}:{password}'.encode()).decode('utf-8')

    response = client.post('/login', headers={"Authorization": f"Basic {credentials}"})
    data = json.loads(response.data.decode('utf-8'))  # Ensure decoding from bytes to string

    assert response.status_code == 200
    assert 'token' in data

def test_protected_route_without_token(client):
    """Test accessing a protected route without a token"""
    response = client.get('/protected')
    assert response.status_code == 401
    assert b'Token is missing!' in response.data

def test_protected_route_with_token(client):
    """Test accessing a protected route with a valid token"""
    # First, login to get a token
    username = 'testuser'
    password = 'testpassword'
    credentials = base64.b64encode(f'{username}:{password}'.encode()).decode('utf-8')
    login_response = client.post('/login', headers={"Authorization": f"Basic {credentials}"})
    token = json.loads(login_response.data.decode('utf-8')).get('token','')
    # Now, try to access a protected route with the token
    response = client.get('/protected', headers={'x-access-token': token})
    assert response.status_code == 200
    assert b'Welcome' in response.data
