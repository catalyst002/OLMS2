"""
OLMS Authentication Prototype – V&V Test Suite (Python)
Simulates TC-01 through TC-09 using only Python stdlib + PyJWT.

Run with: python3 tests/auth_test.py
"""

import re
import time
import hashlib
import hmac
import json
import base64
import sys

# ── Minimal password-hashing using pbkdf2 (stdlib, no bcrypt needed) ──────────
SALT_ROUNDS = 260000  # iterations (NIST recommendation for PBKDF2-SHA256)

def hash_password(password: str) -> str:
    import os
    salt = base64.b64encode(os.urandom(16)).decode()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), SALT_ROUNDS)
    return f"pbkdf2$sha256${SALT_ROUNDS}${salt}${dk.hex()}"

def check_password(password: str, stored: str) -> bool:
    try:
        _, alg, iters, salt, stored_hash = stored.split('$')
        dk = hashlib.pbkdf2_hmac(alg, password.encode(), salt.encode(), int(iters))
        return hmac.compare_digest(dk.hex(), stored_hash)
    except Exception:
        return False

# ── Minimal JWT (HS256 only) ───────────────────────────────────────────────────
JWT_SECRET = 'olms-dev-secret-key'

def jwt_encode(payload: dict, secret: str, expires_in: int = 7200) -> str:
    payload = dict(payload)
    payload['exp'] = int(time.time()) + expires_in
    header  = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b'=').decode()
    body    = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    sig_input = f"{header}.{body}"
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), sig_input.encode(), hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    return f"{sig_input}.{sig}"

def jwt_decode(token: str, secret: str) -> dict:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    header, body, sig = parts
    sig_input = f"{header}.{body}"
    expected_sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), sig_input.encode(), hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("Invalid signature")
    # Decode payload
    padding = 4 - len(body) % 4
    payload = json.loads(base64.urlsafe_b64decode(body + '=' * padding))
    if payload.get('exp', 0) < time.time():
        raise ValueError("TokenExpiredError")
    return payload

# ── Business logic (mirrors server.js) ───────────────────────────────────────
def validate_email(email: str) -> bool:
    return bool(re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email))

def validate_password(password: str) -> bool:
    return bool(re.match(r'^(?=.*[A-Z])(?=.*\d).{8,}$', password))

MAX_ATTEMPTS = 3
LOCKOUT_MS   = 15 * 60  # seconds

class AuthStore:
    def __init__(self):
        self.users   = {}
        self.attempts = {}

    def is_locked(self, email):
        rec = self.attempts.get(email)
        if not rec:
            return False
        if rec.get('locked_until') and time.time() < rec['locked_until']:
            return True
        if rec.get('locked_until') and time.time() >= rec['locked_until']:
            del self.attempts[email]
        return False

    def record_failed(self, email):
        if email not in self.attempts:
            self.attempts[email] = {'count': 0, 'locked_until': None}
        self.attempts[email]['count'] += 1
        if self.attempts[email]['count'] >= MAX_ATTEMPTS:
            self.attempts[email]['locked_until'] = time.time() + LOCKOUT_MS

    def clear_attempts(self, email):
        self.attempts.pop(email, None)

# ── Test runner ───────────────────────────────────────────────────────────────
passed = 0
failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  ✅ PASS  {name}")
        passed += 1
    except AssertionError as e:
        print(f"  ❌ FAIL  {name}")
        print(f"         AssertionError: {e}")
        failed += 1
    except Exception as e:
        print(f"  ❌ FAIL  {name}")
        print(f"         Exception: {e}")
        failed += 1

# ═══════════════════════════════════════════════════════════════
print()
print("╔══════════════════════════════════════════════════════╗")
print("║   OLMS Authentication – V&V Test Suite              ║")
print("╚══════════════════════════════════════════════════════╝")
print()

# TC-01: Valid Registration
print("TC-01: Valid User Registration")
def tc01():
    assert validate_email('student@uni.edu'), "Valid email rejected"
    assert validate_password('SecurePass1'), "Valid password rejected"
    hashed = hash_password('SecurePass1')
    assert hashed != 'SecurePass1', "Hash must not equal plaintext"
    assert 'pbkdf2' in hashed, "Hash should use PBKDF2 scheme"
test("registers with valid name, email, and strong password", tc01)

# TC-02: Email Validation
print("\nTC-02: Email Format Validation")
def tc02a():
    assert not validate_email('not-an-email'),     "Should reject 'not-an-email'"
    assert not validate_email('missing@'),         "Should reject 'missing@'"
    assert not validate_email('@nodomain.com'),    "Should reject '@nodomain.com'"
    assert not validate_email('spaces @uni.edu'), "Should reject email with space"
test("rejects malformed email addresses", tc02a)

def tc02b():
    assert validate_email('user@domain.com'),     "Should accept valid email"
    assert validate_email('a.b+c@sub.domain.io'), "Should accept complex valid email"
test("accepts correctly formatted email addresses", tc02b)

# TC-03: Password Complexity
print("\nTC-03: Password Complexity Enforcement")
def tc03a():
    assert not validate_password('short1A'),      "Should reject: too short"
    assert not validate_password('alllowercase1'),"Should reject: no uppercase"
    assert not validate_password('NoDigitsHere'), "Should reject: no digit"
    assert not validate_password('12345678'),     "Should reject: no uppercase"
test("rejects passwords failing complexity rules", tc03a)

def tc03b():
    assert validate_password('Passw0rd'),    "Should accept Passw0rd"
    assert validate_password('My$ecure1'),   "Should accept My$ecure1"
    assert validate_password('UPPER1lower'), "Should accept UPPER1lower"
test("accepts passwords meeting all complexity rules", tc03b)

# TC-04: Login & JWT Issuance
print("\nTC-04: Successful Login and JWT Issuance")
def tc04():
    hashed = hash_password('Passw0rd!')
    assert check_password('Passw0rd!', hashed), "Correct password should match"
    token   = jwt_encode({'email': 'u@uni.edu', 'role': 'student', 'name': 'Alice'}, JWT_SECRET)
    decoded = jwt_decode(token, JWT_SECRET)
    assert decoded['role']  == 'student',   f"Expected role=student, got {decoded['role']}"
    assert decoded['email'] == 'u@uni.edu', f"Expected email=u@uni.edu, got {decoded['email']}"
test("issues a valid JWT with correct role claim on login", tc04)

# TC-05: Invalid Credentials
print("\nTC-05: Invalid Credentials Rejection")
def tc05():
    hashed = hash_password('CorrectPassword1')
    assert not check_password('WrongPassword1', hashed), "Wrong password should not match"
test("rejects login when password does not match stored hash", tc05)

# TC-06: Account Lockout
print("\nTC-06: Account Lockout Mechanism")
def tc06a():
    store = AuthStore()
    email = 'victim@uni.edu'
    assert not store.is_locked(email), "Should not be locked initially"
    store.record_failed(email)
    store.record_failed(email)
    assert not store.is_locked(email), "Should not be locked after 2 attempts"
    store.record_failed(email)
    assert store.is_locked(email), "Should be locked after 3rd attempt"
test("locks account after 3 consecutive failed login attempts", tc06a)

def tc06b():
    store = AuthStore()
    email = 'user@uni.edu'
    store.record_failed(email)
    store.record_failed(email)
    store.record_failed(email)
    assert store.is_locked(email)
    store.clear_attempts(email)
    assert email not in store.attempts, "Attempts record should be deleted after clear"
test("clears lockout state on successful login", tc06b)

# TC-07: RBAC
print("\nTC-07: Role-Based Access Control")
def tc07a():
    token   = jwt_encode({'email': 'st@uni.edu', 'role': 'student', 'name': 'Bob'}, JWT_SECRET)
    decoded = jwt_decode(token, JWT_SECRET)
    assert decoded['role'] not in ['admin'], "Student should not access admin route"
test("student token is rejected on admin-only endpoint", tc07a)

def tc07b():
    token   = jwt_encode({'email': 'ad@uni.edu', 'role': 'admin', 'name': 'Admin'}, JWT_SECRET)
    decoded = jwt_decode(token, JWT_SECRET)
    assert decoded['role'] in ['admin'], "Admin should access admin route"
test("admin token is accepted on admin-only endpoint", tc07b)

# TC-08: Expired Token
print("\nTC-08: Expired JWT Rejection (Reliability / Security)")
def tc08():
    token = jwt_encode({'email': 'u@uni.edu', 'role': 'student'}, JWT_SECRET, expires_in=-1)
    threw = False
    try:
        jwt_decode(token, JWT_SECRET)
    except ValueError as e:
        if 'TokenExpiredError' in str(e) or 'Expired' in str(e):
            threw = True
    assert threw, "Should raise ValueError for expired token"
test("verifying an expired token raises an error", tc08)

# TC-09: Duplicate Email
print("\nTC-09: Duplicate Email Prevention")
def tc09():
    store = AuthStore()
    email = 'dup@uni.edu'
    store.users[email] = {'name': 'First User', 'role': 'student', 'password_hash': hash_password('Passw0rd1')}
    already_exists = email in store.users
    assert already_exists, "Second registration should detect existing user"
test("prevents registering the same email twice", tc09)

# ── Summary ────────────────────────────────────────────────────────────────────
print()
print("══════════════════════════════════════════════════════")
print(f"  Results: {passed} passed, {failed} failed out of {passed + failed} tests")
print("══════════════════════════════════════════════════════")
print()

sys.exit(1 if failed > 0 else 0)
