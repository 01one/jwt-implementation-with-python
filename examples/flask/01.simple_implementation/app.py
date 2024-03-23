from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response
import base64
import hashlib
import hmac
import json
import datetime

app = Flask(__name__)

# Secret key for encoding/decoding JWT
SECRET_KEY = '234231465457'

def encode_jwt(payload):
	header = {'typ': 'JWT', 'alg': 'HS256'}
	header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
	payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')

	# Base64 encoding header and payload
	encoded_header = base64.urlsafe_b64encode(header_json).decode('utf-8')
	encoded_payload = base64.urlsafe_b64encode(payload_json).decode('utf-8')

	# Creating signature
	signature = hmac.new(SECRET_KEY.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'), hashlib.sha256)
	encoded_signature = base64.urlsafe_b64encode(signature.digest()).decode('utf-8')

	# Combining all parts to form JWT
	jwt_token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"

	return jwt_token

def decode_jwt(jwt_token):
	encoded_header, encoded_payload, encoded_signature = jwt_token.split('.')
	payload = base64.urlsafe_b64decode(encoded_payload.encode('utf-8')).decode('utf-8')
	return json.loads(payload)

@app.route('/')
def home():
	# Check if user is already logged in
	jwt_token = request.cookies.get('jwt_token')
	if jwt_token:
		try:
			payload = decode_jwt(jwt_token)
			print(payload)
			return redirect(url_for('dashboard'))
		except:
			pass  # Invalid token, proceed to login
	return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
	# Dummy authentication
	if request.form['username'] == 'username' and request.form['password'] == 'password':
		# Create JWT token with payload
		payload = {'username': request.form['username']}
		jwt_token = encode_jwt(payload)
		
		# Set the JWT token in a cookie
		response = make_response(redirect(url_for('dashboard')))
		response.set_cookie('jwt_token', jwt_token, httponly=True, expires=datetime.datetime.now() + datetime.timedelta(minutes=30))
		
		return response
	else:
		return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/dashboard')
def dashboard():
	# Retrieve JWT token from the cookie
	jwt_token = request.cookies.get('jwt_token')
	if jwt_token:
		try:
			payload = decode_jwt(jwt_token)
			return render_template('dashboard.html', username=payload['username'])
		except:
			return jsonify({'message': 'Invalid token'}), 401
	else:
		return jsonify({'message': 'Token missing'}), 401
		
@app.route('/logout')
def logout():
	# Clear the JWT token from the cookie
	response = make_response(redirect(url_for('home')))
	response.set_cookie('jwt_token', '', expires=0)
	return response
		
		

if __name__ == '__main__':
	app.run(debug=True)
