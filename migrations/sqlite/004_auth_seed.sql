-- ============================================================================
-- Migration: 004_auth_seed.sql
-- Target Database: auth.db (SQLite)
-- Purpose: Seed Default Identity Accounts for Role-Based Access Control (RBAC)
-- Description:
--   Populates four standard compliance and operational test identities:
--   1. `admin`   - Role: 'admin'   (System Administrator / Full governance)
--   2. `auditor` - Role: 'auditor' (Lead Compliance Officer / Read-only audits)
--   3. `alice`   - Role: 'user'    (Senior Developer / Task management)
--   4. `bob`     - Role: 'user'    (Support Engineer / Task workflows)
--
-- Security Note:
--   All passwords are pre-computed using bcrypt with cost factor 10:
--   - Admin@123 -> $2b$10$T.EG5pXeQP81wX3xLiMTXu5lz7XZhjg.PBTYAHTm8P88bGkv4JR6C
--   - Audit@123 -> $2b$10$CBI3spoWrIo7VQFoS5ImUe9jC.8.R5l/z8dGnqHO69IEGsfnItkAG
--   - User@123  -> $2b$10$hOk8QyOKnzIssFIfVPLzA.RqrhDOLOBKVjoy4q/2LcKEIhPrCyKwC
-- ============================================================================

-- Admin account (System Administrator)
INSERT OR IGNORE INTO users (id, username, password_hash, role, full_name, created_at, updated_at)
VALUES (
  '2844c2bd-67f9-462c-8340-14d88d9de974',
  'admin',
  '$2b$10$T.EG5pXeQP81wX3xLiMTXu5lz7XZhjg.PBTYAHTm8P88bGkv4JR6C',
  'admin',
  'System Administrator',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

-- Auditor account (Lead Compliance Officer)
INSERT OR IGNORE INTO users (id, username, password_hash, role, full_name, created_at, updated_at)
VALUES (
  '6347c01d-e5a9-400c-96cc-fbae9245d2b3',
  'auditor',
  '$2b$10$CBI3spoWrIo7VQFoS5ImUe9jC.8.R5l/z8dGnqHO69IEGsfnItkAG',
  'auditor',
  'Lead Compliance Officer',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

-- Alice account (Developer standard user)
INSERT OR IGNORE INTO users (id, username, password_hash, role, full_name, created_at, updated_at)
VALUES (
  '63dc4051-60f8-4745-b09e-8a12633c246f',
  'alice',
  '$2b$10$hOk8QyOKnzIssFIfVPLzA.RqrhDOLOBKVjoy4q/2LcKEIhPrCyKwC',
  'user',
  'Alice Johnson (Developer)',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

-- Bob account (Support standard user)
INSERT OR IGNORE INTO users (id, username, password_hash, role, full_name, created_at, updated_at)
VALUES (
  '19094931-8e12-4be3-8d68-da0a4c85d495',
  'bob',
  '$2b$10$TTzHxcyATHtCCoSVu7Xnn.yNwBigVgNlUFXJ4oGw/oydt6EOhWcrW',
  'user',
  'Bob Smith (Support)',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);
