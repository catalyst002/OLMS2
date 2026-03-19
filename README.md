# OLMS Authentication Prototype

**Feature:** US-01 – User Authentication & Role-Based Access Control  
**Assignment:** Software Engineering – Assignment 2  
**Stack:** Node.js · Express · bcryptjs · jsonwebtoken

---

## Prerequisites

- Node.js v18 or later  
- npm v9 or later

---

## Setup & Run

```bash
# 1. Install dependencies
npm install

# 2. Start the server
npm start
# → Server running at http://localhost:3000

# 3. Open the UI
# Navigate to http://localhost:3000 in your browser
```

---

## Demo Accounts (pre-seeded)

| Email | Password | Role |
|---|---|---|
| `admin@olms.edu` | `Admin@1234` | Administrator |
| `prof@olms.edu` | `Prof@1234` | Instructor |

You can also register a new Student or Instructor account via the UI.

---

## Running Tests

```bash
npm test
```

Runs 9 unit/integration test cases covering:
- Valid registration (TC-01)
- Email format validation (TC-02)
- Password complexity enforcement (TC-03)
- JWT issuance on login (TC-04)
- Invalid credential rejection (TC-05)
- Account lockout after 3 failed attempts (TC-06)
- Role-based access control (TC-07)
- Expired JWT rejection (TC-08)
- Duplicate email prevention (TC-09)

---

## API Endpoints

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| POST | `/api/register` | No | Register new account |
| POST | `/api/login` | No | Login, receive JWT |
| GET | `/api/dashboard` | Bearer JWT | Role-specific dashboard |
| GET | `/api/admin/users` | Admin only | List all users |
| GET | `/api/instructor/courses` | Instructor/Admin | List courses |

---

## File Structure

```
olms-auth-prototype/
├── package.json
├── README.md
├── public/
│   └── index.html       # Single-page frontend UI
├── src/
│   └── server.js        # Express REST API
└── tests/
    └── auth.test.js     # V&V test suite (9 test cases)
```

---
