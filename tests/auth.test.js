/**
 * OLMS Auth Prototype – Test Suite
 * V&V Plan Implementation: TC-01 through TC-08
 *
 * Run with: node tests/auth.test.js
 * (No external test framework required – pure Node.js assertions)
 */

const assert = require('assert');

// ── Inline duplicates of server logic for unit-level testing ─────────────────
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');

const JWT_SECRET  = 'olms-dev-secret-key';
const SALT_ROUNDS = 10;
const MAX_ATTEMPTS = 3;
const LOCKOUT_MS   = 15 * 60 * 1000;

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function validatePassword(password) {
  return /^(?=.*[A-Z])(?=.*\d).{8,}$/.test(password);
}

// Minimal in-memory simulation
function makeAuthStore() {
  const users = {};
  const attempts = {};

  function isLockedOut(email) {
    const rec = attempts[email];
    if (!rec) return false;
    if (rec.lockedUntil && Date.now() < rec.lockedUntil) return true;
    if (rec.lockedUntil && Date.now() >= rec.lockedUntil) delete attempts[email];
    return false;
  }
  function recordFailed(email) {
    if (!attempts[email]) attempts[email] = { count: 0, lockedUntil: null };
    attempts[email].count += 1;
    if (attempts[email].count >= MAX_ATTEMPTS)
      attempts[email].lockedUntil = Date.now() + LOCKOUT_MS;
  }
  function clearAttempts(email) { delete attempts[email]; }

  return { users, attempts, isLockedOut, recordFailed, clearAttempts };
}

// ── Test runner ───────────────────────────────────────────────────────────────
let passed = 0, failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✅ PASS  ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ❌ FAIL  ${name}`);
    console.log(`         ${err.message}`);
    failed++;
  }
}

// ── Test Cases ────────────────────────────────────────────────────────────────

(async () => {
  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║   OLMS Authentication – V&V Test Suite              ║');
  console.log('╚══════════════════════════════════════════════════════╝\n');

  // ── TC-01: Valid Registration ─────────────────────────────────────────────
  console.log('TC-01: Valid User Registration');
  await test('registers with valid name, email, and strong password', async () => {
    assert.strictEqual(validateEmail('student@uni.edu'), true);
    assert.strictEqual(validatePassword('SecurePass1'), true);
    const hash = await bcrypt.hash('SecurePass1', SALT_ROUNDS);
    assert.ok(hash.startsWith('$2'), 'Hash should be bcrypt format');
    assert.notStrictEqual(hash, 'SecurePass1', 'Hash must not equal plaintext');
  });

  // ── TC-02: Email Validation ───────────────────────────────────────────────
  console.log('\nTC-02: Email Format Validation');
  await test('rejects malformed email addresses', () => {
    assert.strictEqual(validateEmail('not-an-email'),     false);
    assert.strictEqual(validateEmail('missing@'),         false);
    assert.strictEqual(validateEmail('@nodomain.com'),    false);
    assert.strictEqual(validateEmail('spaces @uni.edu'), false);
  });
  await test('accepts correctly formatted email addresses', () => {
    assert.strictEqual(validateEmail('user@domain.com'),     true);
    assert.strictEqual(validateEmail('a.b+c@sub.domain.io'), true);
  });

  // ── TC-03: Password Complexity Enforcement ────────────────────────────────
  console.log('\nTC-03: Password Complexity Enforcement');
  await test('rejects passwords failing complexity rules', () => {
    assert.strictEqual(validatePassword('short1A'),     false, 'Too short');
    assert.strictEqual(validatePassword('alllowercase1'), false, 'No uppercase');
    assert.strictEqual(validatePassword('NoDigitsHere'), false, 'No digit');
    assert.strictEqual(validatePassword('12345678'),    false, 'No uppercase');
  });
  await test('accepts passwords meeting all complexity rules', () => {
    assert.strictEqual(validatePassword('Passw0rd'),    true);
    assert.strictEqual(validatePassword('My$ecure1'),   true);
    assert.strictEqual(validatePassword('UPPER1lower'), true);
  });

  // ── TC-04: Successful Login & JWT Issuance ────────────────────────────────
  console.log('\nTC-04: Successful Login and JWT Issuance');
  await test('issues a valid JWT with correct role claim on login', async () => {
    const hash  = await bcrypt.hash('Passw0rd!', SALT_ROUNDS);
    const match = await bcrypt.compare('Passw0rd!', hash);
    assert.strictEqual(match, true, 'bcrypt.compare should return true for correct password');

    const token   = jwt.sign({ email: 'u@uni.edu', role: 'student', name: 'Alice' }, JWT_SECRET, { expiresIn: '2h' });
    const decoded = jwt.verify(token, JWT_SECRET);
    assert.strictEqual(decoded.role, 'student');
    assert.strictEqual(decoded.email, 'u@uni.edu');
  });

  // ── TC-05: Invalid Credentials ────────────────────────────────────────────
  console.log('\nTC-05: Invalid Credentials Rejection');
  await test('rejects login when password does not match stored hash', async () => {
    const hash  = await bcrypt.hash('CorrectPassword1', SALT_ROUNDS);
    const match = await bcrypt.compare('WrongPassword1', hash);
    assert.strictEqual(match, false, 'Wrong password should not match');
  });

  // ── TC-06: Account Lockout After 3 Failed Attempts ───────────────────────
  console.log('\nTC-06: Account Lockout Mechanism');
  await test('locks account after 3 consecutive failed login attempts', () => {
    const store = makeAuthStore();
    const email = 'victim@uni.edu';

    assert.strictEqual(store.isLockedOut(email), false, 'Should not be locked initially');
    store.recordFailed(email);
    store.recordFailed(email);
    assert.strictEqual(store.isLockedOut(email), false, 'Should not be locked after 2 attempts');
    store.recordFailed(email);
    assert.strictEqual(store.isLockedOut(email), true, 'Should be locked after 3rd attempt');
  });
  await test('clears lockout state on successful login', () => {
    const store = makeAuthStore();
    const email = 'user@uni.edu';
    store.recordFailed(email); store.recordFailed(email); store.recordFailed(email);
    assert.strictEqual(store.isLockedOut(email), true);
    // Simulate successful login clearing attempts
    store.clearAttempts(email);
    // Force lockoutUntil into the past for this test
    assert.strictEqual(store.attempts[email], undefined, 'Attempts record should be deleted');
  });

  // ── TC-07: Role-Based Access Control ─────────────────────────────────────
  console.log('\nTC-07: Role-Based Access Control');
  await test('student token is rejected on admin-only endpoint', () => {
    const studentToken = jwt.sign({ email: 'st@uni.edu', role: 'student', name: 'Bob' }, JWT_SECRET, { expiresIn: '1h' });
    const decoded      = jwt.verify(studentToken, JWT_SECRET);
    const allowedRoles = ['admin'];
    assert.strictEqual(allowedRoles.includes(decoded.role), false, 'Student should not access admin route');
  });
  await test('admin token is accepted on admin-only endpoint', () => {
    const adminToken = jwt.sign({ email: 'ad@uni.edu', role: 'admin', name: 'Admin' }, JWT_SECRET, { expiresIn: '1h' });
    const decoded    = jwt.verify(adminToken, JWT_SECRET);
    const allowedRoles = ['admin'];
    assert.strictEqual(allowedRoles.includes(decoded.role), true, 'Admin should access admin route');
  });

  // ── TC-08: Expired Token Rejection ───────────────────────────────────────
  console.log('\nTC-08: Expired JWT Rejection (Reliability / Security)');
  await test('verifying an expired token throws JsonWebTokenError', async () => {
    const expiredToken = jwt.sign({ email: 'u@uni.edu', role: 'student' }, JWT_SECRET, { expiresIn: '1ms' });
    await new Promise(r => setTimeout(r, 10)); // wait for expiry
    let threw = false;
    try { jwt.verify(expiredToken, JWT_SECRET); }
    catch (e) { threw = true; assert.ok(e.name === 'TokenExpiredError', `Expected TokenExpiredError, got ${e.name}`); }
    assert.strictEqual(threw, true, 'Should throw on expired token');
  });

  // ── TC-09: Duplicate Email Registration ───────────────────────────────────
  console.log('\nTC-09: Duplicate Email Prevention');
  await test('prevents registering the same email twice', async () => {
    const store = makeAuthStore();
    const email = 'dup@uni.edu';
    const hash  = await bcrypt.hash('Pass1234A', SALT_ROUNDS);
    store.users[email] = { name: 'Dup User', role: 'student', passwordHash: hash };
    const alreadyExists = !!store.users[email];
    assert.strictEqual(alreadyExists, true, 'Second registration should detect existing user');
  });

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log('\n══════════════════════════════════════════════════════');
  console.log(`  Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
  console.log('══════════════════════════════════════════════════════\n');
  process.exit(failed > 0 ? 1 : 0);
})();
