import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import re

# Define constants
SECRET_KEY = '123'
EXPECTED_ISSUER = 'expected_issuer'
EXPECTED_AUDIENCE = 'expected_audience'

# Define regular expression pattern for issuer name
ISSUER_PATTERN = r'^[a-zA-Z0-9_-]+$'
#ISSUER_PATTERN = r'^[a-z0-9_-]{5,20}$'  # 5-20 characters, lowercase letters, numbers, underscore, hyphen

def encode_jwt(payload, expiration_time):
    header = {'typ': 'JWT', 'alg': 'HS256'}
    header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
    
    # Include expiration time in the payload
    payload['exp'] = int(time.time()) + expiration_time
    
    payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    encoded_header = base64.urlsafe_b64encode(header_json).decode('utf-8').rstrip('=')
    encoded_payload = base64.urlsafe_b64encode(payload_json).decode('utf-8').rstrip('=')

    signature = hmac.new(SECRET_KEY.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'), hashlib.sha256)
    encoded_signature = base64.urlsafe_b64encode(signature.digest()).decode('utf-8').rstrip('=')

    jwt_token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"
    return jwt_token

def decode_jwt(jwt_token):
    # Check if the token contains three parts
    parts = jwt_token.split('.')
    if len(parts) != 3:
        return {'error': 'Invalid token format'}

    encoded_header, encoded_payload, encoded_signature = parts

    # Validate and decode the payload
    try:
        payload = base64.urlsafe_b64decode(encoded_payload + '=' * (-len(encoded_payload) % 4)).decode('utf-8')
        decoded_payload = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {'error': 'Invalid payload format'}

    # Validate expiration time
    if 'exp' in decoded_payload:
        if not isinstance(decoded_payload['exp'], int):
            return {'error': 'Expiration time must be an integer'}
        if decoded_payload['exp'] < int(time.time()):
            return {'error': 'Token expired'}

    # Validate issuer using regular expression
    if 'iss' in decoded_payload:
        issuer = decoded_payload['iss']
        if not re.match(ISSUER_PATTERN, issuer):
            return {'error': 'Invalid issuer name format'}

        if issuer != EXPECTED_ISSUER:
            return {'error': 'Invalid issuer'}

    # Validate audience
    if 'aud' in decoded_payload:
        if not isinstance(decoded_payload['aud'], str):
            return {'error': 'Audience must be a string'}
        if EXPECTED_AUDIENCE not in decoded_payload['aud']:
            return {'error': 'Invalid audience'}

    # Validate signature
    expected_signature = base64.urlsafe_b64encode(hmac.new(SECRET_KEY.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'), hashlib.sha256).digest()).decode('utf-8').rstrip('=')
    if not secrets.compare_digest(encoded_signature, expected_signature):
        return {'error': 'Invalid signature'}

    return decoded_payload
    
payload = {'user_id': 1, 'username': 'Our UserName', 'iss': 'expected_issuer', 'aud': 'expected_audience'}


# Set expiration time in seconds (e.g., 1 hour)
expiration_time = 3600

# Encoding the payload into a JWT with expiration time
jwt_token = encode_jwt(payload, expiration_time)
print("Encoded JWT with expiration:", jwt_token)

# Decoding the JWT to retrieve the payload
decoded_payload = decode_jwt(jwt_token)
print("Decoded Payload:", decoded_payload)
