-- ============================================================================
-- Migration Rollback: 006_audit_seed.down.sql
-- Target Database: audit.db (SQLite)
-- Purpose: Rollback baseline audit log records
-- Compliance Note:
--   Because audit.db enforces database-level immutability triggers (WORM),
--   a direct DELETE command will be blocked by `audit_logs_prevent_delete`.
--   For intentional administrative rollback in development/test environments,
--   the trigger must be temporarily dropped, the records removed, and the
--   trigger immediately reinstated.
-- ============================================================================

-- Step 1: Temporarily drop the delete prevention trigger for administrative maintenance
DROP TRIGGER IF EXISTS audit_logs_prevent_delete;

-- Step 2: Remove baseline genesis audit records
DELETE FROM audit_logs 
WHERE event IN ('SYSTEM_INIT', 'SEED_USERS', 'UPDATE_PRODUCT')
  AND user_id IN ('system-root', 'admin-seed-id');

-- Step 3: Re-arm the immutability trigger to protect subsequent logs
CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_delete
BEFORE DELETE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'Audit logs are immutable: DELETE operations are strictly prohibited by compliance policy.');
END;
