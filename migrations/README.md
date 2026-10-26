# 🗄️ AuditPro Database Migrations & Schema Architecture

This directory houses the versioned database migration files and runner for AuditPro's 3-database isolated architecture, as well as Microsoft SQL Server (SSMS) data warehouse replication scripts.

---

## 📁 Directory Structure

```text
migrations/
├── sqlite/                              # SQLite migrations (Application engine)
│   ├── 001_auth_schema.sql             # Users, refresh tokens, credentials
│   ├── 001_auth_schema.down.sql        # Rollback for auth schema
│   ├── 002_business_schema.sql         # Products catalog & compliance tasks
│   ├── 002_business_schema.down.sql    # Rollback for business schema
│   ├── 003_audit_schema.sql            # Audit logs, JWT telemetry, sessions & WORM triggers
│   ├── 003_audit_schema.down.sql       # Rollback for audit schema
│   ├── 004_auth_seed.sql               # Default RBAC seed users (admin, auditor, alice, bob)
│   ├── 004_auth_seed.down.sql          # Rollback for auth seed
│   ├── 005_business_seed.sql           # Seed products catalog & compliance tasks
│   ├── 005_business_seed.down.sql      # Rollback for business seed
│   ├── 006_audit_seed.sql              # Genesis audit trail baseline records
│   └── 006_audit_seed.down.sql         # Rollback for audit seed
│
├── sqlserver/                           # Microsoft SQL Server / SSMS migrations
│   ├── 001_sqlserver_init_schema.sql   # T-SQL DDL for 3-DB setup & unified AuditProDB
│   └── 001_sqlserver_init_schema.down.sql # T-SQL Rollback script
│
├── runner.js                            # Transactional migration CLI engine
└── README.md                            # Architecture documentation
```

---

## 🚀 Migration CLI Commands

| Command | npm Script | Description |
| :--- | :--- | :--- |
| `node migrations/runner.js up` | `npm run migrate` | Applies all unapplied forward migrations in sequence. |
| `node migrations/runner.js down` | `npm run migrate:rollback` | Rolls back the latest batch of applied migrations. |
| `node migrations/runner.js status` | `npm run migrate:status` | Prints an ASCII table detailing migration status across all 3 databases. |
| `node migrations/runner.js reset` | `npm run migrate:reset` | Rolls back all batches and re-applies migrations from scratch. |

---

## 🏛️ Database Schemas & Isolation

### 1. `auth.db` (Identity & Token Management)
- **`users`**: UUID primary key, case-insensitive unique username (`NOCASE`), bcrypt-hashed passwords (cost factor 10), and database-level role constraints (`admin`, `auditor`, `user`).
- **`refresh_tokens`**: Opaque refresh token hash tracking, unique `jti` pairing, expiration timestamps, revocation flags, and `replaced_by_token` pointers to detect and prevent token reuse/replay attacks.
- **Indexes**: `idx_refresh_token_hash`, `idx_refresh_user_id`, `idx_refresh_expires_revoked`.

### 2. `business.db` (Products & Task Workflows)
- **`products`**: Commercial catalog and security appliances with unique `sku`, category, pricing, and stock tracking.
- **`tasks`**: Governance action items with strict check constraints on `priority` (`low`, `medium`, `high`, `urgent`) and `status` (`pending`, `in_progress`, `completed`, `archived`).
- **Indexes**: `idx_tasks_assigned`, `idx_tasks_created_by`, `idx_tasks_status_priority`, `idx_products_sku`, `idx_products_category`.

### 3. `audit.db` (Forensics Vault & WORM Compliance)
- **`audit_logs`**: Write-Once, Read-Many (WORM) audit event repository with actor attributes, action narrative, entity targeting, and timestamps.
- **`jwt_events`**: Cryptographic token issuance, rotation, validation, and revocation audit trail.
- **`user_sessions`**: Session footprint telemetry, login/logout timestamps, accumulated dwell duration, screen view history, and total action counts.
- **Database-Level Immutability Triggers**:
  - `audit_logs_prevent_update`: Emits `RAISE(ABORT)` on any `UPDATE` statement.
  - `audit_logs_prevent_delete`: Emits `RAISE(ABORT)` on any `DELETE` statement.
  - `jwt_events_prevent_update`: Emits `RAISE(ABORT)` on any `UPDATE` statement.
  - `jwt_events_prevent_delete`: Emits `RAISE(ABORT)` on any `DELETE` statement.
  - `user_sessions_prevent_delete`: Emits `RAISE(ABORT)` on any `DELETE` statement.

---

## 🏢 SQL Server / SSMS Enterprise Synchronization

For enterprise compliance mirroring into Microsoft SQL Server or SQL Server Management Studio (SSMS):
- Run `migrations/sqlserver/001_sqlserver_init_schema.sql` in SSMS.
- Script automatically supports both the **isolated 3-database pattern** (`AuditPro_Auth`, `AuditPro_Business`, `AuditPro_Audit`) and the **unified reporting warehouse** (`AuditProDB`).
- Includes T-SQL `INSTEAD OF` triggers that utilize `THROW` to enforce immutability at the SQL Server tier.
