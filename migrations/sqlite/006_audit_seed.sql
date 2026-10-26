-- ============================================================================
-- Migration: 006_audit_seed.sql
-- Target Database: audit.db (SQLite)
-- Purpose: Seed Initial System Audit Log Records for Compliance Baseline
-- Description:
--   Populates immutable genesis records establishing the initial compliance
--   baseline:
--   1. SYSTEM_INIT - Architectural initialization of the 3 isolated databases.
--   2. SEED_USERS - Record of initial identity provisioning and RBAC roles.
--   3. UPDATE_PRODUCT - Baseline demonstration of product price change auditing.
-- ============================================================================

-- Genesis Record 1: System Architecture Initialization
INSERT INTO audit_logs (
  timestamp,
  event,
  user_id,
  username,
  role,
  ip_address,
  action,
  entity_id,
  status
) VALUES (
  DATETIME('now', '-10 minutes'),
  'SYSTEM_INIT',
  'system-root',
  'system',
  'system',
  '127.0.0.1',
  'Initialized 3-DB isolated architecture and enabled SQLite immutable triggers',
  'kernel',
  'SUCCESS'
);

-- Genesis Record 2: User Role Provisioning
INSERT INTO audit_logs (
  timestamp,
  event,
  user_id,
  username,
  role,
  ip_address,
  action,
  entity_id,
  status
) VALUES (
  DATETIME('now', '-8 minutes'),
  'SEED_USERS',
  'system-root',
  'system',
  'system',
  '127.0.0.1',
  'Provisioned standard identity roles: admin, auditor, alice, bob',
  'all',
  'SUCCESS'
);

-- Genesis Record 3: Baseline Product Audit Entry
INSERT INTO audit_logs (
  timestamp,
  event,
  user_id,
  username,
  role,
  ip_address,
  action,
  entity_id,
  status
) VALUES (
  DATETIME('now', '-5 minutes'),
  'UPDATE_PRODUCT',
  'admin-seed-id',
  'admin',
  'admin',
  '192.168.1.100',
  'Adjusted catalog price for Enterprise Firewall Appliance X9',
  'NET-FW-01',
  'SUCCESS'
);
