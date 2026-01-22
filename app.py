from flask import Flask, render_template, request, jsonify, session
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import secrets, base64, json, time, re
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Secure session config
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

# In-memory storage (demo)
vault_data = {}
session_data = {}

# Rate limiting
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # seconds


# ---------------- SECURITY HELPERS ---------------- #

def log_security_event(event, details):
    print(f"[SECURITY] {datetime.now().isoformat()} | {event} | {details}")

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data, key):
    return Fernet(key).encrypt(json.dumps(data).encode()).decode()

def decrypt_data(data, key):
    try:
        return json.loads(Fernet(key).decrypt(data.encode()).decode())
    except Exception:
        return None

def validate_master_password(pw):
    if len(pw) < 12: return False, "Min 12 chars"
    if not re.search(r'[A-Z]', pw): return False, "Uppercase required"
    if not re.search(r'[a-z]', pw): return False, "Lowercase required"
    if not re.search(r'\d', pw): return False, "Number required"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pw): return False, "Special char required"
    return True, ""

def check_rate_limit(identifier):
    now = time.time()

    if identifier in login_attempts:
        attempts, last = login_attempts[identifier]
        if attempts >= MAX_LOGIN_ATTEMPTS:
            if now - last < LOCKOUT_DURATION:
                return False, f"Account locked. Try again in {int(LOCKOUT_DURATION - (now - last))} seconds"
            else:
                login_attempts[identifier] = [1, now]
                return True, ""
        login_attempts[identifier] = [attempts + 1, now]
    else:
        login_attempts[identifier] = [1, now]

    return True, ""


# ---------------- ROUTES ---------------- #

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/create-vault', methods=['POST'])
def create_vault():
    data = request.get_json()
    pw = data.get('master_password')

    valid, msg = validate_master_password(pw)
    if not valid:
        return jsonify({"error": msg}), 400

    salt = secrets.token_bytes(32)
    key = derive_key(pw, salt)

    # 🔐 Verification token (CRITICAL FIX)
    verification = encrypt_data("vault_check", key)

    session_id = secrets.token_hex(16)
    session['session_id'] = session_id
    session['authenticated'] = True
    session['last_activity'] = time.time()

    vault_data[session_id] = {
        "salt": base64.b64encode(salt).decode(),
        "passwords": [],
        "verification": verification
    }

    session_data[session_id] = {
        "encryption_key": key
    }

    log_security_event("VAULT_CREATED", session_id)
    return jsonify({"success": True})


@app.route('/api/unlock-vault', methods=['POST'])
def unlock_vault():
    data = request.get_json()
    pw = data.get("master_password")

    if not vault_data:
        return jsonify({"error": "No vault exists"}), 404

    session_id = list(vault_data.keys())[0]

    # 🔒 Rate limit FIRST
    allowed, msg = check_rate_limit(session_id)
    if not allowed:
        return jsonify({"error": msg}), 429

    salt = base64.b64decode(vault_data[session_id]['salt'])
    key = derive_key(pw, salt)

    # ❗ VERIFY PASSWORD (CRITICAL FIX)
    token = vault_data[session_id]['verification']
    if decrypt_data(token, key) != "vault_check":
        log_security_event("UNLOCK_FAILED", session_id)
        return jsonify({"error": "Invalid master password"}), 401

    # ✅ Success → reset attempts
    login_attempts.pop(session_id, None)

    session['session_id'] = session_id
    session['authenticated'] = True
    session['last_activity'] = time.time()

    session_data[session_id] = {"encryption_key": key}
    log_security_event("VAULT_UNLOCKED", session_id)

    return jsonify({"success": True})


@app.route('/api/add-password', methods=['POST'])
def add_password():
    if not session.get('authenticated'):
        return jsonify({"error": "Unauthorized"}), 401

    sid = session['session_id']
    data = request.get_json()

    entry = {
        "id": secrets.token_hex(8),
        "website": data['website'].strip(),
        "username": data['username'].strip(),
        "password": data['password'],
        "created_at": datetime.now().isoformat()
    }

    enc = encrypt_data(entry, session_data[sid]['encryption_key'])
    vault_data[sid]['passwords'].append(enc)

    return jsonify({"success": True})


@app.route('/api/get-passwords')
def get_passwords():
    if not session.get('authenticated'):
        return jsonify({"error": "Unauthorized"}), 401

    sid = session['session_id']
    key = session_data[sid]['encryption_key']

    result = []
    for e in vault_data[sid]['passwords']:
        d = decrypt_data(e, key)
        result.append({
            "id": d['id'],
            "website": d['website'],
            "username": d['username'],
            "created_at": d['created_at']
        })

    return jsonify({"passwords": result})


@app.route('/api/reveal-password', methods=['POST'])
def reveal_password():
    if not session.get('authenticated'):
        return jsonify({"error": "Unauthorized"}), 401

    sid = session['session_id']
    pid = request.get_json()['password_id']
    key = session_data[sid]['encryption_key']

    for e in vault_data[sid]['passwords']:
        d = decrypt_data(e, key)
        if d['id'] == pid:
            return jsonify({"password": d['password']})

    return jsonify({"error": "Not found"}), 404


@app.route('/api/lock-vault', methods=['POST'])
def lock_vault():
    sid = session.get('session_id')
    session.clear()
    if sid in session_data:
        del session_data[sid]
    log_security_event("VAULT_LOCKED", sid)
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
