import pytest
import time
import jwt
import sqlite3
from app import app, init_db, initialize_keys, encrypt_private_key, decrypt_private_key

@pytest.fixture
def client():
    # Initialize the database and generate keys before each test
    init_db()
    initialize_keys()

    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwks(client):
    """Test the JWKS endpoint to ensure it returns valid keys."""
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()
    assert 'keys' in data
    assert len(data['keys']) > 0  # Ensure at least one valid key is present

def test_auth_valid_token(client):
    """Test that a valid JWT is issued."""
    response = client.post('/auth')
    assert response.status_code == 200
    data = response.get_json()
    token = data['token']
    assert token  # Ensure a token is returned

    # Decode and check expiration time
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded['exp'] > time.time()  # Token should be valid (not expired)

def test_auth_expired_token(client):
    """Test that an expired JWT is issued when requested."""
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = response.get_json()
    token = data['token']
    assert token  # Ensure a token is returned

    # Decode and check expiration time
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded['exp'] < time.time()  # Token should be expired

def test_register_endpoint(client):
    """Test the /register endpoint for successful user registration."""
    payload = {"username": "testuser", "email": "testuser@example.com"}
    response = client.post('/register', json=payload)
    assert response.status_code == 201
    data = response.get_json()
    assert 'password' in data  # Ensure a password is returned to the user

    # Check the database for the newly created user
    conn = sqlite3.connect('jwks_server.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, email FROM users WHERE username = ?", (payload["username"],))
    user = cursor.fetchone()
    conn.close()
    assert user is not None
    assert user[0] == "testuser"
    assert user[1] == "testuser@example.com"

def test_register_duplicate_user(client):
    """Test that registering a duplicate username or email fails."""
    payload = {"username": "testuser", "email": "testuser@example.com"}
    client.post('/register', json=payload)  # First registration
    response = client.post('/register', json=payload)  # Duplicate registration
    assert response.status_code == 409  # Conflict status code

def test_auth_logging(client):
    """Test that successful /auth requests are logged."""
    # Register a user
    payload = {"username": "testuser", "email": "testuser@example.com"}
    response = client.post('/register', json=payload)
    assert response.status_code == 201
    password = response.get_json()["password"]

    # Authenticate the user
    auth_payload = {"username": "testuser", "password": password}
    response = client.post('/auth', json=auth_payload)
    assert response.status_code == 200

    # Check the auth_logs table
    conn = sqlite3.connect('jwks_server.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM auth_logs WHERE user_id = (SELECT id FROM users WHERE username = ?)", ("testuser",))
    log = cursor.fetchone()
    conn.close()
    assert log is not None  # Ensure the log entry exists
    assert log[1] == "127.0.0.1"  # Default IP for Flask test client

def test_auth_rate_limit(client):
    """Test that the /auth endpoint is rate-limited."""
    payload = {"username": "testuser", "email": "testuser@example.com"}
    response = client.post('/register', json=payload)
    assert response.status_code == 201
    password = response.get_json()["password"]

    auth_payload = {"username": "testuser", "password": password}

    # Send 10 requests within the limit
    for _ in range(10):
        response = client.post('/auth', json=auth_payload)
        assert response.status_code == 200

    # Send an 11th request to exceed the rate limit
    response = client.post('/auth', json=auth_payload)
    assert response.status_code == 429  # Too Many Requests

def test_key_encryption():
    """Test the encryption and decryption of private keys."""
    original_key = b"MySuperSecretPrivateKey"
    encrypted = encrypt_private_key(original_key)
    decrypted = decrypt_private_key(encrypted["encrypted_key"], encrypted["iv"])
    assert decrypted == original_key  # Ensure the original and decrypted keys match

def test_database_key_storage():
    """Test that keys are correctly stored in the database."""
    conn = sqlite3.connect('jwks_server.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM keys")
    keys = cursor.fetchall()
    conn.close()
    assert len(keys) >= 2  # Ensure at least two keys (one expired, one valid) are stored
    for key in keys:
        assert key[1] is not None  # Check that the key blob is not null
        assert key[2] is not None  # Check that the IV is not null
