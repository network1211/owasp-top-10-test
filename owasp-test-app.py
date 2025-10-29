from flask import Flask, request, jsonify, send_from_directory, g
import jwt
import datetime
import os
from jwt.exceptions import InvalidTokenError
from flask_swagger_ui import get_swaggerui_blueprint
from jwcrypto import jwk
from base64 import b64decode
import uuid

app = Flask(__name__)

# ========== Global Auth Check =====
def require_bearer_or_401():
    if g.basic_auth_valid:
        return None  # allow basic bypass if you still want it
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing Authorization header"}), 401
    token = auth_header.split()[1]
    try:
        jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])
        return None
    except InvalidTokenError:
        return jsonify({"error": "Invalid or expired token"}), 401
    except Exception:
        return jsonify({"error": "Malformed or missing token"}), 401

# ========== Static Setup ==========
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={ 'app_name': "OWASP API Vulnerabilities Combined App" }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# ========== JWT Key Setup ==========
with open('private.pem', 'r') as f:
    PRIVATE_KEY = f.read()

with open('public.pem', 'r') as f:
    PUBLIC_KEY = f.read()

# Sequential users: 11..70
USERS = {
    str(i): {
        "username": str(i),
        "email": f"user{i}@example.com",
        "group": "user"
    }
    for i in range(11, 81)
}

# ========== Basic Auth Bypass Check ==========
@app.before_request
def allow_all_if_basic_auth_valid():
    g.basic_auth_valid = False
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        try:
            encoded = auth_header.split(" ")[1]
            decoded = b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
            if username == "user-test" and password == "password":
                g.basic_auth_valid = True
        except Exception:
            pass

# ========== JWKS URL =========
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    key = jwk.JWK.from_pem(PUBLIC_KEY.encode())
    return jsonify({
        "keys": [key.export(as_dict=True)]
    })

# ========== 1. BOLA ==========
@app.route('/api/v1/invoices/<invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    # Restrict invoice_id to 1001..1070
    try:
        inv = int(invoice_id)
    except ValueError:
        return jsonify({"error": "Invoice not found"}), 404
    if inv < 1001 or inv > 1070:
        return jsonify({"error": "Invoice not found"}), 404

    # JWT required (validate signature/claims)
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing Authorization header"}), 401

    token = auth_header.split()[1]
    try:
        # Validate JWT (we don't use its username for the response anymore)
        jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])
    except InvalidTokenError:
        return jsonify({"error": "Invalid or expired token"}), 401
    except Exception:
        return jsonify({"error": "Malformed or missing token"}), 401

    # Static mapping: invoice_id -> user_id (1001->11, ..., 1070->80)
    mapped_user_id = str(inv - 990)
    if mapped_user_id not in USERS:
        return jsonify({"error": "User not found for invoice"}), 404

    # Deterministic 3-digit amount (static per invoice_id)
    amount = ((inv * 37) % 900) + 100   # always 100..999, same result for same invoice

    return jsonify({
        "invoice_id": str(inv),
        "user_id": mapped_user_id,
        "Amount": amount
    })

# ========== 2. Broken Authentication ==========
@app.route('/api/v1/auth/data', methods=['GET'])
def api_key_auth():
    if g.basic_auth_valid:
        return jsonify({"message": "Access granted via Basic Auth"})

    if request.args.get('apikey') and request.args.get('regToken'):
        return jsonify({"data": "Authenticated via API key and regToken"})
    return jsonify({"error": "Missing API key or token"}), 401

@app.route('/api/v1/jwt/data', methods=['GET'])
def broken_jwt():
    if g.basic_auth_valid:
        return jsonify({"message": "Access granted via Basic Auth"})

    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({"error": "No Bearer token"}), 401
    token = auth.split()[1]
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return jsonify({"message": "JWT accepted", "token_data": decoded})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ========== 3. BOPLA ==========
@app.route('/api/v1/pii', methods=['GET'])
def pii_exposure():
    if g.basic_auth_valid:
        return jsonify({"ssn": "123-45-6789", "dob": "1990-01-01"})
    return jsonify({"ssn": "123-45-6789", "dob": "1990-01-01"})

@app.route('/api/v1/users', methods=['POST'])
def mass_assignment():
    if g.basic_auth_valid:
        data = request.get_json()
        return jsonify({"user": data}), 201
    data = request.get_json()
    return jsonify({"user": data}), 201

# ========== 4. Unrestricted Resource Consumption ==========
@app.route('/initiate_forgot_password', methods=['POST'])
def resource_consumption():
    gate = require_bearer_or_401()
    if gate:
        return gate
    if g.basic_auth_valid:
        user_number = request.get_json().get("user_number")
        return jsonify({
            "reset_sms": "POST /sms/send_reset_pass_code",
            "Host": "willyo.net",
            "phone_number": user_number,
            "cost_charge": "$0.05"
        })
    user_number = request.get_json().get("user_number")
    return jsonify({
        "reset_sms": "POST /sms/send_reset_pass_code",
        "Host": "willyo.net",
        "phone_number": user_number,
        "cost_charge": "$0.05"
    })

# ========== 5. BFLA ==========
@app.route('/api/v1/data', methods=['GET', 'POST'])
def secured_data():
    if g.basic_auth_valid:
        return jsonify({"message": "Access granted via Basic Auth"})

    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header.replace('Bearer ', '')
    try:
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])
        return jsonify({
            "user": decoded['sub'],
            "group": decoded['group'],
            "method": request.method
        })
    except InvalidTokenError as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 401
    except Exception as e:
        return jsonify({"error": "Malformed or missing JWT"}), 401

@app.route('/generate_token/<username>', methods=['GET'])
def generate_token(username):
    user = USERS.get(username)  # now only 11..70 exist
    if not user:
        return jsonify({"error": "Invalid user"}), 404

    now = datetime.datetime.utcnow()
    expiration = now + datetime.timedelta(days=30)
    payload = {
        "sub": user["username"],
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": expiration,
        "nbf": now,
        "username": user["username"],
        "group": user.get("group", "user")
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256')
    return jsonify({"token": token})

# ========== 6. Business Logic Abuse ==========
tickets_remaining = 100

@app.route('/api/v1/tickets/buy', methods=['POST'])
def ticket_buy():
    gate = require_bearer_or_401()
    if gate:
        return gate
    global tickets_remaining
    if g.basic_auth_valid:
        req = request.get_json()
        qty = int(req.get('quantity', 1))
        qty = min(qty, tickets_remaining)
        tickets_remaining -= qty
        return jsonify({"message": f"Bought {qty} tickets", "left": tickets_remaining})

    req = request.get_json()
    qty = int(req.get('quantity', 1))
    if tickets_remaining <= 0:
        return jsonify({"message": "All tickets are sold out"}), 403
    qty = min(qty, tickets_remaining)
    tickets_remaining -= qty
    return jsonify({"message": f"Bought {qty} tickets", "left": tickets_remaining})

@app.route('/api/v1/tickets/reset', methods=['POST'])
def reset_tickets():
    gate = require_bearer_or_401()
    if gate:
        return gate
    global tickets_remaining
    tickets_remaining = 100
    return jsonify({"message": "Tickets have been reset", "total": tickets_remaining}), 200

# ========== 7. SSRF ==========
@app.route('/api/v1/profile/picture', methods=['POST'])
def profile_picture():
    gate = require_bearer_or_401()
    if gate:
        return gate
    if g.basic_auth_valid:
        url = request.get_json().get('image_url')
        return jsonify({"message": "Image set", "url": url})

    url = request.get_json().get('image_url')
    if url in ['/etc/passwd', 'file:///etc/passwd']:
        return jsonify({"content": "root:x:0:0:root:/root:/bin/bash\n..."})
    return jsonify({"message": "Image set", "url": url})

# ========== 8. Misconfig (CORS *) ==========
@app.route('/api/v1/config/sample', methods=['GET'])
def config_sample():
    gate = require_bearer_or_401()
    if gate:
        return gate
    if g.basic_auth_valid:
        resp = jsonify({"message": "Weak CORS"})
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp

    resp = jsonify({"message": "Weak CORS"})
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

# ========== 9. Shadow API (NOT documented) ==========
@app.route('/internal/api/userdata', methods=['GET'])
def shadow_api():
    if g.basic_auth_valid:
        return jsonify({"credit_card": "4111 1111 1111 1111", "dob": "1991-01-01"})

    return jsonify({"credit_card": "4111 1111 1111 1111", "dob": "1991-01-01"})

# ========== 10. Unsafe Consumption ==========
@app.route('/api/v1/userinfo', methods=['GET'])
def unsafe_consume():
    gate = require_bearer_or_401()
    if gate:
        return gate
    if g.basic_auth_valid:
        return jsonify({"name": "John", "email": "john@example.com", "phone": "+1-555-123-4567"})

    if request.headers.get('X-UCA') == 'Malicious':
        return jsonify({"payload": "<script>alert('XSS')</script> OR 1=1"})
    return jsonify({"name": "John", "email": "john@example.com", "phone": "+1-555-123-4567"})

# ========== Static Swagger Download ==========
@app.route('/swagger/download', methods=['GET'])
def download_swagger():
    return send_from_directory('static', 'swagger.json', as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=True)
