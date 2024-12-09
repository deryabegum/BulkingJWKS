from flask import Flask, jsonify, request
import jwt
import time
import sqlite3
import os
import uuid
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from base64 import b64encode, b64decode
from os import urandom

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app)

# Constants
ENCRYPTION_KEY = os.environ.get("NOT_MY_KEY")
if not ENCRYPTION_KEY:
    raise EnvironmentError("Environment variable 'NOT_MY_KEY' not set.")
ENCRYPTION_KEY = ENCRYPTION_KEY.encode()[:32]  # Ensure 32 bytes for AES-256

ph = PasswordHasher()

# Database initialization
def init_db():
    conn = sqlite3.connect('jwks_server.db')
    cursor = conn.cursor()

    # Keys table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            iv TEXT NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Auth logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

# AES Encryption for private keys
def encrypt_private_key(private_key: bytes) -> dict:
    iv = urandom(16)  # Generate random IV
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_key = private_key.ljust((len(private_key) + 15) // 16 * 16)  # Pad to block size
    encrypted_key = encryptor.update(padded_key) + encryptor.finalize()
    return {"iv": b64encode(iv).decode(), "encrypted_key": b64encode(encrypted_key).decode()}

def decrypt_private_key(encrypted_key: str, iv: str) -> bytes:
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(b64decode(iv)), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_key = decryptor.update(b64decode(encrypted_key)) + decryptor.finalize()
    return decrypted_key.strip()

# Store encrypted key
def store_key(private_key, expiry):
    conn = sqlite3.connect('jwks_server.db')
    cursor = conn.cursor()
    pem_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted = encrypt_private_key(pem_key)
    cursor.execute("INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)", 
                   (encrypted["encrypted_key"], encrypted["iv"], expiry))
    conn.commit()
    conn.close()

# Initialize RSA keys
def initialize_keys():
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    store_key(expired_key, int(time.time()) - 3600)
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    store_key(valid_key, int(time.time()) + 3600)

# Retrieve keys
def get_key(expired):
    conn = sqlite3.connect('jwks_server.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT kid, key, iv FROM keys WHERE exp < ?" if expired else "SELECT kid, key, iv FROM keys WHERE exp > ?",
        (int(time.time()),)
    )
    result = cursor.fetchone()
    conn.close()
    if result:
        kid, encrypted_key, iv = result
        private_key = serialization.load_pem_private_key(
            decrypt_private_key(encrypted_key, iv), password=None
        )
        return kid, private_key
    return None, None

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    conn = sqlite3.connect('jwks_server.db')
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key, iv FROM keys WHERE exp > ?", (int(time.time()),))
    keys = []
    for row in cursor.fetchall():
        kid, encrypted_key, iv = row
        private_key = serialization.load_pem_private_key(
            decrypt_private_key(encrypted_key, iv), password=None
        )
        public_key = private_key.public_key()
        jwk_key = jwk.JWK.from_pem(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        jwk_key_obj = jwk_key.export(as_dict=True)
        jwk_key_obj['kid'] = str(kid)
        keys.append(jwk_key_obj)
    conn.close()
    return jsonify({"keys": keys}), 200

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    if not username or not email:
        return jsonify({"error": "Username and email are required"}), 400
    password = str(uuid.uuid4())
    password_hash = ph.hash(password)
    conn = sqlite3.connect('jwks_server.db')
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409
    finally:
        conn.close()
    return jsonify({"password": password}), 201

@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired', 'false') == 'true'
    kid, private_key = get_key(expired)

    if private_key is None:
        return jsonify({"error": "No appropriate key found"}), 404

    expiry_time = time.time() - 3600 if expired else time.time() + 3600
    token = jwt.encode(
        {
            'sub': 'userABC',
            'exp': expiry_time
        },
        private_key,
        algorithm='RS256',
        headers={"kid": str(kid)}
    )
    return jsonify({"token": token}), 200
    user_id, password_hash = user
    try:
        ph.verify(password_hash, password)
    except:
        return jsonify({"error": "Invalid credentials"}), 401
    ip = request.remote_addr
    cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (ip, user_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Authentication successful"}), 200

if __name__ == '__main__':
    init_db()
    initialize_keys()
    app.run(host='0.0.0.0', port=8080)
