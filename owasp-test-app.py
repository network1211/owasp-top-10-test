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

USERS = {
    "user1": {"username": "user1", "group": "user"},
    "admin1": {"username": "admin1", "group": "admin"},
    "1762": {"username": "attacker", "email": "attacker@example.com", "group": "user"},
    "1083": {"username": "1083", "email": "user1083@example.com", "group": "user"},
    "1376": {"username": "1376", "email": "user1376@example.com", "group": "user"},
    "1399": {"username": "1399", "email": "user1399@example.com", "group": "user"},
    "1174": {"username": "1174", "email": "user1174@example.com", "group": "user"},
    "1122": {"username": "1122", "email": "user1122@example.com", "group": "user"},
    "1297": {"username": "1297", "email": "user1297@example.com", "group": "user"},
    "1417": {"username": "1417", "email": "user1417@example.com", "group": "user"},
    "1730": {"username": "1730", "email": "user1730@example.com", "group": "user"},
    "1098": {"username": "1098", "email": "user1098@example.com", "group": "user"},
    "1742": {"username": "1742", "email": "user1742@example.com", "group": "user"},
    "1784": {"username": "1784", "email": "user1784@example.com", "group": "user"},
    "1009": {"username": "1009", "email": "user1009@example.com", "group": "user"},
    "1833": {"username": "1833", "email": "user1833@example.com", "group": "user"},
    "1448": {"username": "1448", "email": "user1448@example.com", "group": "user"},
    "1171": {"username": "1171", "email": "user1171@example.com", "group": "user"},
    "1276": {"username": "1276", "email": "user1276@example.com", "group": "user"},
    "1657": {"username": "1657", "email": "user1657@example.com", "group": "user"},
    "1754": {"username": "1754", "email": "user1754@example.com", "group": "user"},
    "1877": {"username": "1877", "email": "user1877@example.com", "group": "user"},
    "1381": {"username": "1381", "email": "user1381@example.com", "group": "user"},
    "1459": {"username": "1459", "email": "user1459@example.com", "group": "user"},
    "1923": {"username": "1923", "email": "user1923@example.com", "group": "user"},
    "1134": {"username": "1134", "email": "user1134@example.com", "group": "user"},
    "1543": {"username": "1543", "email": "user1543@example.com", "group": "user"},
    "1331": {"username": "1331", "email": "user1331@example.com", "group": "user"},
    "1885": {"username": "1885", "email": "user1885@example.com", "group": "user"},
    "1018": {"username": "1018", "email": "user1018@example.com", "group": "user"},
    "1034": {"username": "1034", "email": "user1034@example.com", "group": "user"},
    "1192": {"username": "1192", "email": "user1192@example.com", "group": "user"},
    "1961": {"username": "1961", "email": "user1961@example.com", "group": "user"},
    "1703": {"username": "1703", "email": "user1703@example.com", "group": "user"},
    "1227": {"username": "1227", "email": "user1227@example.com", "group": "user"},
    "1312": {"username": "1312", "email": "user1312@example.com", "group": "user"},
    "1346": {"username": "1346", "email": "user1346@example.com", "group": "user"},
    "1955": {"username": "1955", "email": "user1955@example.com", "group": "user"},
    "1596": {"username": "1596", "email": "user1596@example.com", "group": "user"},
    "1869": {"username": "1869", "email": "user1869@example.com", "group": "user"},
    "1235": {"username": "1235", "email": "user1235@example.com", "group": "user"},
    "1810": {"username": "1810", "email": "user1810@example.com", "group": "user"},
    "1471": {"username": "1471", "email": "user1471@example.com", "group": "user"},
    "1365": {"username": "1365", "email": "user1365@example.com", "group": "user"},
    "1243": {"username": "1243", "email": "user1243@example.com", "group": "user"},
    "1934": {"username": "1934", "email": "user1934@example.com", "group": "user"},
    "1765": {"username": "1765", "email": "user1765@example.com", "group": "user"},
    "1679": {"username": "1679", "email": "user1679@example.com", "group": "user"},
    "1858": {"username": "1858", "email": "user1858@example.com", "group": "user"},
    "1519": {"username": "1519", "email": "user1519@example.com", "group": "user"},
    "1602": {"username": "1602", "email": "user1602@example.com", "group": "user"},
    "1047": {"username": "1047", "email": "user1047@example.com", "group": "user"},
    "1555": {"username": "1555", "email": "user1555@example.com", "group": "user"}
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
@app.route('/api/v1/users/<user_id>', methods=['GET'])
def get_user(user_id):
    # Return 404 if the user doesn't exist in the USERS "DB"
    if user_id not in USERS:
        return jsonify({"error": "User not found"}), 404

    # If Basic Auth bypass is valid (no JWT required)
    if g.basic_auth_valid:
        return jsonify({
            "message": "Access granted via Basic Auth",
            "username": user_id,
            "email": f"user{user_id}@example.com"
        })

    # Otherwise require Bearer token (validated, but not used for values)
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing Authorization header"}), 401

    token = auth_header.replace('Bearer ', '')
    try:
        # Validate signature & claims; ignore contents for response shaping
        jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])
    except InvalidTokenError:
        return jsonify({"error": "Invalid or expired token"}), 401
    except Exception:
        return jsonify({"error": "Malformed or missing token"}), 401

    # Respond using the path parameter only
    return jsonify({
        "message": "Access granted via Bearer token",
        "username": user_id,
        "email": f"user{user_id}@example.com"
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
    user = USERS.get(username)
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
        "username": user.get("username"),
        "group": user.get("group", "user")
    }

    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256')
    return jsonify({"token": token})

# ========== 6. Business Logic Abuse ==========
tickets_remaining = 100

@app.route('/api/v1/tickets/buy', methods=['POST'])
def ticket_buy():
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
    global tickets_remaining
    tickets_remaining = 100
    return jsonify({"message": "Tickets have been reset", "total": tickets_remaining}), 200

# ========== 7. SSRF ==========
@app.route('/api/v1/profile/picture', methods=['POST'])
def profile_picture():
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
    app.run(host='0.0.0.0', port=5003, debug=True)
