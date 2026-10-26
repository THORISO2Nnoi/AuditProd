-- ============================================================================
-- Migration Rollback: 004_auth_seed.down.sql
-- Target Database: auth.db (SQLite)
-- Purpose: Remove default seeded identities
-- Caution: Deletes the standard demo users and any child refresh tokens
--          linked to them via cascade foreign keys.
-- ============================================================================

DELETE FROM users 
WHERE username IN ('admin', 'auditor', 'alice', 'bob');
