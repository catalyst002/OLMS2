/**
 * OLMS Authentication Prototype – server.js
 * Feature: US-01 User Authentication & Role-Based Access Control
 */

const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const path    = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const JWT_SECRET      = 'olms-dev-secret-key';
const JWT_EXPIRES_IN  = '2h';
const SALT_ROUNDS     = 10;
const MAX_ATTEMPTS    = 3;
const LOCKOUT_MS      = 15 * 60 * 1000;

const users = {};
const loginAttempts = {};

const DASHBOARDS = {
  student:    { links: ['My Courses', 'Assignments', 'Grades', 'Track Progress'] },
  instructor: { links: ['My Courses', 'Grade Submissions', 'Upload Materials', 'Announcements'] },
  admin:      { links: ['User Management', 'Reports', 'System Settings', 'Audit Log'] }
};

(async () => {
  users['admin@olms.edu'] = {
    name: 'System Admin',
    role: 'admin',
    passwordHash: await bcrypt.hash('Admin@1234', SALT_ROUNDS)
  };
  users['prof@olms.edu'] = {
    name: 'Dr. Smith',
    role: 'instructor',
    passwordHash: await bcrypt.hash('Prof@1234', SALT_ROUNDS)
  };
  console.log('Demo accounts seeded.');
})();

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function validatePassword(password) {
  return /^(?=.*[A-Z])(?=.*\d).{8,}$/.test(password);
}
function isLockedOut(email) {
  const rec = loginAttempts[email];
  if (!rec) return false;
  if (rec.lockedUntil && Date.now() < rec.lockedUntil) return true;
  if (rec.lockedUntil && Date.now() >= rec.lockedUntil) delete loginAttempts[email];
  return false;
}
function recordFailedAttempt(email) {
  if (!loginAttempts[email]) loginAttempts[email] = { count: 0, lockedUntil: null };
  loginAttempts[email].count += 1;
  if (loginAttempts[email].count >= MAX_ATTEMPTS)
    loginAttempts[email].lockedUntil = Date.now() + LOCKOUT_MS;
}
function clearAttempts(email) { delete loginAttempts[email]; }

function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'Missing or invalid Authorization header.' });
  try {
    req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token expired or invalid.' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: `Access denied. Required role: ${roles.join(' or ')}.` });
    next();
  };
}

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'name, email, and password are required.' });
  if (!validateEmail(email))
    return res.status(400).json({ error: 'Invalid email format.' });
  if (!validatePassword(password))
    return res.status(400).json({ error: 'Password must be at least 8 characters with one uppercase letter and one digit.' });
  const userRole = ['student', 'instructor'].includes(role) ? role : 'student';
  if (users[email])
    return res.status(409).json({ error: 'An account with this email already exists.' });
  users[email] = { name, role: userRole, passwordHash: await bcrypt.hash(password, SALT_ROUNDS) };
  return res.status(201).json({ message: 'Registration successful.', user: { name, email, role: userRole } });
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'email and password are required.' });
  if (isLockedOut(email)) {
    const remaining = Math.ceil((loginAttempts[email].lockedUntil - Date.now()) / 60000);
    return res.status(429).json({ error: `Account locked. Try again in ${remaining} minute(s).` });
  }
  const user = users[email];
  if (!user) { recordFailedAttempt(email); return res.status(401).json({ error: 'Invalid credentials.' }); }
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    recordFailedAttempt(email);
    const rec = loginAttempts[email];
    const left = rec ? Math.max(MAX_ATTEMPTS - rec.count, 0) : MAX_ATTEMPTS;
    return res.status(401).json({ error: `Invalid credentials. ${left} attempt(s) remaining.` });
  }
  clearAttempts(email);
  const token = jwt.sign({ email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  const dash = DASHBOARDS[user.role] || DASHBOARDS.student;
  return res.status(200).json({
    message: `Welcome, ${user.name}!`,
    token,
    user: { name: user.name, email, role: user.role },
    links: dash.links          // <-- links now included in login response
  });
});

// GET /api/dashboard
app.get('/api/dashboard', authenticate, (req, res) => {
  const dash = DASHBOARDS[req.user.role] || DASHBOARDS.student;
  return res.json({ message: `Welcome, ${req.user.name}!`, role: req.user.role, links: dash.links });
});

// GET /api/admin/users
app.get('/api/admin/users', authenticate, requireRole('admin'), (req, res) => {
  const userList = Object.entries(users).map(([email, u]) => ({ email, name: u.name, role: u.role }));
  return res.json({ users: userList });
});

// GET /api/instructor/courses
app.get('/api/instructor/courses', authenticate, requireRole('instructor', 'admin'), (req, res) => {
  return res.json({ courses: ['CS101 – Intro to Programming', 'CS301 – Data Structures'] });
});

const PORT = 3003;
app.listen(PORT, () => console.log(`OLMS Auth Server running on http://localhost:${PORT}`));
module.exports = app;
