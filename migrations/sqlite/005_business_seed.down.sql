-- ============================================================================
-- Migration Rollback: 005_business_seed.down.sql
-- Target Database: business.db (SQLite)
-- Purpose: Remove default seeded products and tasks
-- Caution: Deletes the baseline demo catalog products and seeded workflow tasks.
-- ============================================================================

-- Remove seeded baseline tasks
DELETE FROM tasks 
WHERE id IN (
  'task-00000000-0000-0000-0000-000000000001',
  'task-00000000-0000-0000-0000-000000000002',
  'task-00000000-0000-0000-0000-000000000003',
  'task-00000000-0000-0000-0000-000000000004'
);

-- Remove seeded baseline products
DELETE FROM products 
WHERE sku IN (
  'NET-FW-01',
  'CRYPTO-HSM-9',
  'STRG-VLT-04',
  'LIC-ZTG-100',
  'CLOUD-BST-22'
);
