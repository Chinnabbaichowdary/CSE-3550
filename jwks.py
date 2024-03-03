from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
from jwt.utils import base64url_encode, bytes_from_int
import json
import uuid
import jwt

app = Flask(__name__)

# Storage for JSON Web Key Set (JWKS)
jwks_data = {"keys": []}

# Handle JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    return jsonify(jwks_data)

# Handle authentication endpoint
@app.route('/auth', methods=['POST'])
@app.route('/auth?expired=true', methods=['POST'])
@app.route('/auth?expired=false', methods=['POST'])
def authenticate():
    is_expired = request.args.get('expired') == "true"
    private_key = generate_key_pair()
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    key_id = str(uuid.uuid4())
    expiration_time = (datetime.now(tz=timezone.utc) - timedelta(seconds=3600)) if is_expired else (datetime.now(tz=timezone.utc) + timedelta(seconds=3600))
    jwt_token = jwt.encode({"exp": expiration_time}, private_key_bytes, algorithm="RS256", headers={"kid": key_id})
    jwk = {
        "kty": "RSA",
        "kid": key_id,
        "alg": "RS256",
        "n": base64url_encode(bytes_from_int(public_key.public_numbers().n)).decode("UTF-8"),
        "e": base64url_encode(bytes_from_int(public_key.public_numbers().e)).decode("UTF-8"),
        "use": "sig",
    }
    if expiration_time > datetime.now(tz=timezone.utc):
        jwks_data["keys"].append(jwk)
    return jwt_token

# Generate RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key

# Handling GET request to the authentication endpoint
@app.route('/auth', methods=['GET'])
@app.route('/auth?expired=true', methods=['GET'])
@app.route('/auth?expired=false', methods=['GET'])
def get_auth():
    return "Authentication endpoint. Please use POST request to obtain a JWT token."

if __name__ == '__main__':
    app.run(debug=True, port=8080)

