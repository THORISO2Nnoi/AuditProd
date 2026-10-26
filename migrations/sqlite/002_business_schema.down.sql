-- ============================================================================
-- Migration Rollback: 002_business_schema.down.sql
-- Target Database: business.db (SQLite)
-- Purpose: Safely teardown business domain models (products, tasks)
-- Caution: Drops all operational product inventory and workflow tasks.
-- ============================================================================

-- Drop indexes
DROP INDEX IF EXISTS idx_products_category;
DROP INDEX IF EXISTS idx_products_sku;
DROP INDEX IF EXISTS idx_tasks_status_priority;
DROP INDEX IF EXISTS idx_tasks_created_by;
DROP INDEX IF EXISTS idx_tasks_assigned;

-- Drop domain tables
DROP TABLE IF EXISTS tasks;
DROP TABLE IF EXISTS products;
