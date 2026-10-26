-- ============================================================================
-- Migration: 003_audit_schema.sql
-- Target Database: audit.db (SQLite)
-- Purpose: Initialize Immutable Forensics Audit Vault, JWT Telemetry & Session Footprints
-- Compliance Scope:
--   - SOC 2 Type II: CC6.8, CC7.2, CC7.3 (Tamper-evident audit logging)
--   - HIPAA Security Rule: 45 CFR § 164.312(b) (Audit controls & integrity)
--   - PCI-DSS 4.0: Requirement 10 (Log and monitor all access to system components)
-- Description:
--   Establishes the Write-Once, Read-Many (WORM) audit architecture:
--   1. `audit_logs` - Immutable record of all system events, mutations, and security attempts.
--   2. `jwt_events` - Cryptographic token lifecycle ledger (jti tracking, rotation, revokes).
--   3. `user_sessions` - Forensic user activity footprints, dwell times, and view histories.
--   4. SQLite Database-Level Immutability Triggers - RAISE(ABORT) blocks any UPDATE or DELETE
--      even if issued directly through sqlite3 CLI by a malicious or compromised actor.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- PRAGMA Configuration
-- ----------------------------------------------------------------------------
-- Enable WAL mode for high concurrency non-blocking log ingestion
PRAGMA journal_mode = WAL;

-- Enforce foreign keys
PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- Table: audit_logs
-- Description:
--   Core forensics log table. Records all mutations, authentication events,
--   tamper alerts, and administrative actions.
--   PROTECTED BY SQL IMMUTABILITY TRIGGERS: Write-Once, Read-Many.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
  -- id: Monotonically increasing sequential primary key
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  -- timestamp: Exact UTC timestamp when event occurred (default: CURRENT_TIMESTAMP)
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

  -- event: High-level classification code (e.g. 'LOGIN', 'LOGOUT', 'CREATE_PRODUCT', 'IMMUTABILITY_TAMPER_ATTEMPT')
  event TEXT NOT NULL,

  -- user_id: UUID of the actor who performed the action (NULL for unauthenticated guests)
  user_id TEXT,

  -- username: Username handle of the actor at the moment of logging
  username TEXT,

  -- role: Role authorization tier of actor at event execution ('admin', 'auditor', 'user', 'guest')
  role TEXT,

  -- ip_address: Remote client IPv4 or IPv6 address (e.g. '127.0.0.1', '192.168.1.100', '::1')
  ip_address TEXT,

  -- action: Comprehensive human-readable narrative explaining what occurred
  action TEXT NOT NULL,

  -- entity_id: Identifier of the primary object acted upon (product SKU, task UUID, user UUID)
  entity_id TEXT,

  -- status: Execution outcome indicator ('SUCCESS', 'FAILED', 'BLOCKED')
  status TEXT DEFAULT 'SUCCESS'
);

-- ----------------------------------------------------------------------------
-- Table: jwt_events
-- Description:
--   Cryptographic token lifecycle audit trail. Tracks every access token issuance,
--   refresh token rotation, validation check, and revocation event by JTI.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jwt_events (
  -- id: Monotonically increasing sequential event ID
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  -- timestamp: UTC time of cryptographic token operation
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

  -- jti: Unique JSON Web Token ID (UUID) claim from token payload
  jti TEXT NOT NULL,

  -- event_type: Lifecycle phase ('LOGIN', 'REFRESH_TOKEN', 'TOKEN_REVOCATION', 'LOGOUT', 'REPLAY_ATTACK_DETECTED')
  event_type TEXT NOT NULL,

  -- user_id: Principal identifier associated with the token
  user_id TEXT,

  -- username: Principal username handle
  username TEXT,

  -- endpoint: API route requested during token evaluation (e.g. '/api/auth/refresh')
  endpoint TEXT,

  -- ip_address: Originating network address
  ip_address TEXT,

  -- user_agent: Browser or HTTP client User-Agent string
  user_agent TEXT,

  -- details: Technical metadata, token replacement hash pointers, or security flags
  details TEXT
);

-- ----------------------------------------------------------------------------
-- Table: user_sessions
-- Description:
--   Aggregated live session tracker and historical activity footprint.
--   Captures login timestamps, last active heartbeats, logout events, total active
--   dwell duration, screen views visited, and total actions performed.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_sessions (
  -- id: Sequential session ID
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  -- jti: Unique JWT ID identifying the session credentials (enforces one session record per token family)
  jti TEXT UNIQUE NOT NULL,

  -- user_id: Associated user UUID
  user_id TEXT,

  -- username: Associated user handle
  username TEXT NOT NULL,

  -- role: Active user role
  role TEXT,

  -- ip_address: Initial login IP address
  ip_address TEXT,

  -- user_agent: Browser environment client string
  user_agent TEXT,

  -- login_time: Initial sign-in timestamp (UTC)
  login_time DATETIME DEFAULT CURRENT_TIMESTAMP,

  -- last_active: Most recent heartbeat or user interaction timestamp
  last_active DATETIME DEFAULT CURRENT_TIMESTAMP,

  -- logout_time: Explicit sign-out timestamp (NULL while session remains active)
  logout_time DATETIME,

  -- duration_seconds: Total time spent in system (accumulated through heartbeats and session finalization)
  duration_seconds INTEGER DEFAULT 0,

  -- formatted_duration: Human-readable duration string (e.g. '14m 32s', '2h 15m')
  formatted_duration TEXT DEFAULT '0s',

  -- status: Session state ('ACTIVE', 'CLOSED', 'TERMINATED', 'EXPIRED')
  status TEXT DEFAULT 'ACTIVE',

  -- last_view: Name of the last dashboard or workspace view visited
  last_view TEXT DEFAULT 'Dashboard',

  -- total_actions: Counter of API mutations and requests performed during this session
  total_actions INTEGER DEFAULT 0,

  -- created_at: Record creation timestamp
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- Indexes
-- ----------------------------------------------------------------------------
-- Audit log filtering by username
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs(username);

-- Audit log filtering by event type
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event);

-- Audit log chronological range queries (compliance timeline scans)
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

-- JWT forensics query by token JTI
CREATE INDEX IF NOT EXISTS idx_jwt_events_jti ON jwt_events(jti);

-- Session lookup by active token JTI
CREATE INDEX IF NOT EXISTS idx_user_sessions_jti ON user_sessions(jti);

-- Session filtering by username for user activity analysis
CREATE INDEX IF NOT EXISTS idx_user_sessions_username ON user_sessions(username);

-- Session filtering by status and active time
CREATE INDEX IF NOT EXISTS idx_user_sessions_status ON user_sessions(status, last_active);

-- ----------------------------------------------------------------------------
-- 🔐 DATABASE-LEVEL IMMUTABILITY TRIGGERS
-- Compliance Mandate: Write-Once, Read-Many (WORM)
-- Prevents ANY modification or deletion of forensics audit data, even if executed
-- directly through the sqlite3 command-line interface or an injected query.
-- ----------------------------------------------------------------------------

-- 1. audit_logs: Block all UPDATE statements
CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_update
BEFORE UPDATE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'Audit logs are immutable: UPDATE operations are strictly prohibited by compliance policy.');
END;

-- 2. audit_logs: Block all DELETE statements
CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_delete
BEFORE DELETE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'Audit logs are immutable: DELETE operations are strictly prohibited by compliance policy.');
END;

-- 3. jwt_events: Block all UPDATE statements
CREATE TRIGGER IF NOT EXISTS jwt_events_prevent_update
BEFORE UPDATE ON jwt_events
BEGIN
  SELECT RAISE(ABORT, 'JWT events log is immutable: UPDATE operations are strictly prohibited.');
END;

-- 4. jwt_events: Block all DELETE statements
CREATE TRIGGER IF NOT EXISTS jwt_events_prevent_delete
BEFORE DELETE ON jwt_events
BEGIN
  SELECT RAISE(ABORT, 'JWT events log is immutable: DELETE operations are strictly prohibited.');
END;

-- 5. user_sessions: Block all DELETE statements
-- Note: UPDATE operations are allowed on user_sessions so active sessions can record
-- heartbeats, duration, last view, and logout time. Once written, however, sessions
-- cannot be expunged or deleted.
CREATE TRIGGER IF NOT EXISTS user_sessions_prevent_delete
BEFORE DELETE ON user_sessions
BEGIN
  SELECT RAISE(ABORT, 'User session history is immutable: DELETE operations are strictly prohibited.');
END;
