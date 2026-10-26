-- ============================================================================
-- Migration Rollback: 003_audit_schema.down.sql
-- Target Database: audit.db (SQLite)
-- Purpose: Safely teardown forensics audit tables, immutability triggers, and indexes
-- Important Notice:
--   Because the tables are protected by WORM immutability triggers that RAISE(ABORT)
--   on DELETE, the triggers must be explicitly DROPPED first before tables can be removed.
-- Caution: Drops all historical audit trails, security event records, and session data.
-- ============================================================================

-- Step 1: Drop immutability triggers first
DROP TRIGGER IF EXISTS user_sessions_prevent_delete;
DROP TRIGGER IF EXISTS jwt_events_prevent_delete;
DROP TRIGGER IF EXISTS jwt_events_prevent_update;
DROP TRIGGER IF EXISTS audit_logs_prevent_delete;
DROP TRIGGER IF EXISTS audit_logs_prevent_update;

-- Step 2: Drop indexes
DROP INDEX IF EXISTS idx_user_sessions_status;
DROP INDEX IF EXISTS idx_user_sessions_username;
DROP INDEX IF EXISTS idx_user_sessions_jti;
DROP INDEX IF EXISTS idx_jwt_events_jti;
DROP INDEX IF EXISTS idx_audit_timestamp;
DROP INDEX IF EXISTS idx_audit_event;
DROP INDEX IF EXISTS idx_audit_username;

-- Step 3: Drop audit tables
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS jwt_events;
DROP TABLE IF EXISTS audit_logs;
