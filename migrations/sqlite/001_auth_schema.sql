-- ============================================================================
-- Migration: 001_auth_schema.sql
-- Target Database: auth.db (SQLite)
-- Purpose: Initialize Authentication & Identity Management Schema
-- Compliance Scope: SOC 2 Type II (CC6.1, CC6.2) / HIPAA Access Controls (§164.312(a))
-- Description:
--   Creates the core identity tables for AuditPro:
--   1. `users` - Secure credentials store with bcrypt hashing and RBAC checks.
--   2. `refresh_tokens` - Cryptographic refresh token lifecycle with rotation,
--      revocation flags, and parent-child rotation pointers.
--   3. Associated indexes for rapid credential and token lookup.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- PRAGMA Configuration
-- ----------------------------------------------------------------------------
-- Enable Write-Ahead Logging (WAL) for high concurrency and crash resilience
PRAGMA journal_mode = WAL;

-- Enforce foreign key constraints across relational tables
PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- Table: users
-- Description:
--   Houses principal identities, role assignments, and salted bcrypt hashes.
--   Never stores plaintext passwords.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  -- id: Unique RFC 4122 v4 UUID string identifying the user across all systems
  id TEXT PRIMARY KEY,

  -- username: Unique login handle.
  -- NOCASE collation ensures case-insensitive uniqueness (e.g. 'Admin' == 'admin'),
  -- preventing impersonation attacks and credential confusion.
  username TEXT UNIQUE NOT NULL COLLATE NOCASE,

  -- password_hash: Salted bcrypt hash (cost factor >= 10) representing the user password.
  password_hash TEXT NOT NULL,

  -- role: Role-Based Access Control (RBAC) tier.
  -- Constrained to 'admin', 'auditor', or 'user' at the database level to
  -- strictly prevent unauthorized privilege escalation.
  role TEXT NOT NULL CHECK(role IN ('admin', 'auditor', 'user')),

  -- full_name: Display name or legal name of the user for compliance reporting.
  full_name TEXT NOT NULL,

  -- created_at: ISO-8601 UTC timestamp of account creation.
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  -- updated_at: ISO-8601 UTC timestamp of the latest profile or credential update.
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- Table: refresh_tokens
-- Description:
--   Stores cryptographically secure rotated refresh tokens paired with short-lived
--   JWT access tokens. Supports token family tracking and instant revocation.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
  -- id: Unique RFC 4122 v4 UUID identifying the token record
  id TEXT PRIMARY KEY,

  -- user_id: Foreign key referencing the parent user.
  -- ON DELETE CASCADE ensures tokens are cleaned up when a user account is deleted.
  user_id TEXT NOT NULL,

  -- token_hash: SHA-256 or bcrypt hash of the opaque refresh token string.
  -- Raw token strings are never stored at rest.
  token_hash TEXT NOT NULL,

  -- jti: Unique JWT ID identifier embedded in the access/refresh token claims.
  -- Used for forensics tracking and detecting stolen/replayed token families.
  jti TEXT NOT NULL,

  -- expires_at: Absolute expiration timestamp (default: 7 days from issuance).
  expires_at DATETIME NOT NULL,

  -- created_at: Timestamp when this refresh token was issued.
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  -- revoked: Boolean flag (0 = valid/active, 1 = revoked).
  -- Revoked tokens immediately reject refresh requests.
  revoked INTEGER DEFAULT 0,

  -- replaced_by_token: Token rotation pointer.
  -- Holds the token_hash of the successor token issued during rotation.
  -- If a request arrives using a token that already has replaced_by_token set,
  -- reuse is detected (token theft) and the entire session family is revoked.
  replaced_by_token TEXT,

  -- Foreign Key Constraint
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- Indexes
-- ----------------------------------------------------------------------------
-- Optimize constant-time lookup when validating incoming refresh token hashes
CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens(token_hash);

-- Optimize retrieval of all active sessions belonging to a specific user
CREATE INDEX IF NOT EXISTS idx_refresh_user_id ON refresh_tokens(user_id);

-- Optimize token lifecycle cleanup queries for expired or revoked tokens
CREATE INDEX IF NOT EXISTS idx_refresh_expires_revoked ON refresh_tokens(expires_at, revoked);
