# 🛡️ AuditPro - Secure Audit Logging Application Architecture

[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL%20Mode-003B57.svg)](https://www.sqlite.org/)
[![Security](https://img.shields.io/badge/Security-SOC2%20%7C%20HIPAA%20Compliant-success.svg)](#security--compliance)

**AuditPro** is a full-stack, enterprise-grade secure audit logging platform built with strict architectural database isolation, cryptographic JWT token lifecycle management, database-level immutability triggers, and real-time diff tracking.

---

## 🌟 Key Features

- **3-Database Compliant Architecture**:
  - `auth.db`: Manages user identities, bcrypt-hashed credentials, and rotated refresh tokens.
  - `business.db`: Houses business domain models (products catalog and task workflows).
  - `audit.db`: WORM-style (Write-Once, Read-Many) immutable forensics audit logs with SQL triggers preventing any `UPDATE` or `DELETE`.
- **Role-Based Access Control (RBAC)**:
  - `admin`: Full administrative control, system metrics, user provisioning, and business domain operations.
  - `auditor`: Compliance officer interface with read-only forensics queries, tamper verification, and CSV export.
  - `user`: Standard access to assigned tasks and personal product entries.
- **Deep Audit Logging & Diff Tracking**:
  - Automatically captures `timestamp`, `event`, `user_id`, `username`, `role`, `ip_address`, `user_agent`, `action`, `entity_type`, `entity_id`, `before_snapshot`, `after_snapshot`, and JSON field `diff`.
- **Cryptographic JWT Lifecycle**:
  - Short-lived Access Tokens (15m) paired with rotated Refresh Tokens (7d) featuring unique `jti` (JWT ID) tracking and revocation protection.
- **Interactive Single Page Application (SPA)**:
  - Responsive, modern dashboard with dark-mode glassmorphism aesthetics, live filtering, role switching, real-time audit event timeline, and tamper verification simulation.

---

## 🏗️ System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                       Client Browser                        │
│                 (Vanilla HTML5 / CSS3 / JS)                 │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / REST APIs
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    Express.js REST Engine                   │
│   ┌───────────────────┐               ┌─────────────────┐   │
│   │   verifyJWT.js    │ ◄───────────► │ requireRole.js  │   │
│   └───────────────────┘               └─────────────────┘   │
└──────┬───────────────────────┬───────────────────────┬──────┘
       │                       │                       │
       ▼                       ▼                       ▼
┌──────────────┐        ┌──────────────┐        ┌──────────────┐
│   auth.db    │        │ business.db  │        │   audit.db   │
│ (Identities, │        │  (Products,  │        │  (Immutable  │
│ Tokens, JTI) │        │    Tasks)    │        │  Triggers)   │
└──────────────┘        └──────────────┘        └──────────────┘
```

---

## 🚀 Quick Start

### 1. Prerequisites
- **Node.js** v18+ 
- **npm** v9+

### 2. Installation
```bash
git clone https://github.com/THORISO2Nnoi/AuditProd.git
cd AuditProd
npm install
```

### 3. Environment Configuration
Copy the sample environment file:
```bash
cp .env.example .env
```
Default parameters in `.env`:
```ini
PORT=3000
JWT_SECRET=auditpro_super_secure_jwt_access_secret_key_compliance_ready_2026
JWT_EXPIRY=15m
REFRESH_SECRET=auditpro_super_secure_refresh_token_rotation_secret_2026
REFRESH_EXPIRY=7d
NODE_ENV=development
```

### 4. Running the Application
```bash
# Start server (auto-seeds default users and sample catalog)
npm start
```

### 5. Database Migrations
Manage database schemas and initial seed data across all 3 isolated SQLite databases:
```bash
# Check current migration status
npm run migrate:status

# Run all pending migrations
npm run migrate

# Roll back the latest migration batch
npm run migrate:rollback

# Reset and re-apply all migrations from scratch
npm run migrate:reset
```
*For Microsoft SQL Server / SSMS migrations, refer to [`migrations/sqlserver/001_sqlserver_init_schema.sql`](migrations/sqlserver/001_sqlserver_init_schema.sql).*

Visit the dashboard in your browser:
👉 **[http://localhost:3000](http://localhost:3000)**

---

## 👥 Demo Credentials

The application automatically seeds standard test roles on first run:

| Role | Username | Password | Access Scope |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `Admin@123` | Full system governance, metrics, users & catalog management |
| **Auditor** | `auditor` | `Audit@123` | Read-only forensic logs, tamper analysis, compliance exports |
| **User** | `alice` | `User@123` | Task management, view products catalog |
| **User** | `bob` | `User@123` | Secondary standard user for task assignment testing |

---

## 📡 API Overview

### Authentication (`/api/auth`)
- `POST /api/auth/login` - Authenticate credentials and receive access + refresh token
- `POST /api/auth/refresh` - Rotate refresh token and issue fresh access token
- `POST /api/auth/logout` - Revoke active refresh token family
- `GET /api/auth/me` - Retrieve current session identity

### Audit & Forensics (`/api/audit`)
- `GET /api/audit/logs` - Query immutable logs (supports filtering by date, user, action, and entity)
- `GET /api/audit/logs/:id` - Detailed record view with before/after state diff
- `GET /api/audit/verify` - Check database triggers and verify log chain integrity
- `GET /api/audit/export` - Export compliance-ready audit trail in CSV format

### Business Domain (`/api/products` & `/api/tasks`)
- `GET /api/products` - List products
- `POST /api/products` - Create product (Logged to `audit.db`)
- `PUT /api/products/:id` - Update product with JSON diff recording
- `DELETE /api/products/:id` - Remove product with snapshot retention
- `GET /api/tasks` - List tasks
- `POST /api/tasks` - Create task
- `PUT /api/tasks/:id` - Update status / assignees

### System Health (`/api/health`)
- `GET /api/health` - Live connection test across all 3 databases (`auth.db`, `business.db`, `audit.db`)

---

## 🔒 Security & Compliance

1. **Database-Level Immutability**:
   `audit.db` registers SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers that execute `RAISE(ABORT, ...)` preventing manual or programmatic record modification.
2. **Password Security**:
   Bcrypt hashing with salt rounds = 10.
3. **Token Invalidation**:
   Refresh tokens store unique `jti` hashes. Stolen or reused tokens trigger an immediate session revocation across the family.

---

## 📄 License
This project is licensed under the **ISC License**.
