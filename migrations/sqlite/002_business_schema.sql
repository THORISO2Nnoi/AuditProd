-- ============================================================================
-- Migration: 002_business_schema.sql
-- Target Database: business.db (SQLite)
-- Purpose: Initialize Business Domain Models (Products Catalog & Task Workflows)
-- Compliance Scope: SOC 2 Common Criteria CC6.8 (Integrity of Operations)
-- Description:
--   Creates domain tables strictly isolated from authentication and audit logs:
--   1. `products` - Commercial and hardware inventory catalog with unique SKU.
--   2. `tasks` - Operational, compliance, and governance workflow tasks.
--   3. Associated indexing structures for performance optimization.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- PRAGMA Configuration
-- ----------------------------------------------------------------------------
-- WAL mode enables non-blocking concurrent reads while writes are processing
PRAGMA journal_mode = WAL;

-- Foreign key enforcement for referential integrity
PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- Table: products
-- Description:
--   Catalog of products, hardware units, cryptographic modules, and software
--   licenses managed through AuditPro. Changes to these records trigger
--   state diffs that are captured in audit.db.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS products (
  -- id: Unique RFC 4122 v4 UUID string representing the product item
  id TEXT PRIMARY KEY,

  -- name: Display title of the product/appliance
  name TEXT NOT NULL,

  -- sku: Stock Keeping Unit identifier.
  -- Must be strictly unique across the catalog to prevent inventory ambiguity.
  sku TEXT UNIQUE NOT NULL,

  -- category: Functional category (e.g. 'Security Hardware', 'Software Licenses', 'Cloud Infrastructure')
  category TEXT NOT NULL,

  -- price: Monetary value with floating-point precision (REAL in SQLite)
  price REAL NOT NULL,

  -- stock: Count of physical units or available digital seats currently in inventory
  stock INTEGER NOT NULL,

  -- description: Technical specifications, capabilities, or compliance certifications
  description TEXT,

  -- created_by: Username of the administrator who created the catalog entry
  created_by TEXT NOT NULL,

  -- created_at: Creation timestamp in ISO-8601 UTC
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  -- updated_at: Last modification timestamp in ISO-8601 UTC
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- Table: tasks
-- Description:
--   Compliance action items, internal audit tickets, and operational duties
--   assigned to staff members. Status transitions are monitored and audited.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tasks (
  -- id: Unique RFC 4122 v4 UUID identifying the task ticket
  id TEXT PRIMARY KEY,

  -- title: Short summary of the work or compliance review required
  title TEXT NOT NULL,

  -- description: In-depth scope of work, relevant standards (e.g. PCI-DSS 10.2), and notes
  description TEXT,

  -- priority: Urgency classification constrained to 4 recognized levels
  priority TEXT NOT NULL CHECK(priority IN ('low', 'medium', 'high', 'urgent')),

  -- status: Lifecycle progress status of the task
  status TEXT NOT NULL CHECK(status IN ('pending', 'in_progress', 'completed', 'archived')),

  -- assigned_to: Username of the user responsible for completing the task
  assigned_to TEXT NOT NULL,

  -- created_by: Username of the supervisor or admin who opened the task
  created_by TEXT NOT NULL,

  -- due_date: Deadline for completion formatted as YYYY-MM-DD
  due_date TEXT,

  -- created_at: Creation timestamp in ISO-8601 UTC
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  -- updated_at: Last status or detail modification timestamp in ISO-8601 UTC
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- Indexes
-- ----------------------------------------------------------------------------
-- Optimize filtering tasks by assignee (e.g. "My Tasks" view for logged-in user)
CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_to);

-- Optimize filtering tasks by creator/supervisor
CREATE INDEX IF NOT EXISTS idx_tasks_created_by ON tasks(created_by);

-- Optimize filtering tasks by status and priority for workflow kanban views
CREATE INDEX IF NOT EXISTS idx_tasks_status_priority ON tasks(status, priority);

-- Optimize product catalog searches by SKU
CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku);

-- Optimize product catalog filtering by category
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
