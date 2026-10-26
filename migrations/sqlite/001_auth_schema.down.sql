-- ============================================================================
-- Migration Rollback: 001_auth_schema.down.sql
-- Target Database: auth.db (SQLite)
-- Purpose: Safely teardown authentication tables, indexes, and constraints
-- Caution: Running this rollback permanently drops all user identities,
--          credentials, and active session tokens.
-- ============================================================================

-- Disable foreign key checks during teardown to avoid dependency locking
PRAGMA foreign_keys = OFF;

-- Drop dependent token indexes first
DROP INDEX IF EXISTS idx_refresh_expires_revoked;
DROP INDEX IF EXISTS idx_refresh_user_id;
DROP INDEX IF EXISTS idx_refresh_token_hash;

-- Drop refresh_tokens table (child table)
DROP TABLE IF EXISTS refresh_tokens;

-- Drop users table (parent identity table)
DROP TABLE IF EXISTS users;

-- Re-enable foreign key constraints
PRAGMA foreign_keys = ON;
