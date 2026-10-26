-- ============================================================================
-- Migration: 005_business_seed.sql
-- Target Database: business.db (SQLite)
-- Purpose: Seed Default Product Catalog Items and Compliance Workflow Tasks
-- Description:
--   Populates representative hardware products, cryptographic storage appliances,
--   software licenses, and compliance governance tasks across priorities and statuses.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Products Catalog Seed
-- ----------------------------------------------------------------------------
INSERT OR IGNORE INTO products (id, name, sku, category, price, stock, description, created_by, created_at, updated_at)
VALUES (
  'prod-00000000-0000-0000-0000-000000000001',
  'Enterprise Firewall Appliance X9',
  'NET-FW-01',
  'Security Hardware',
  2499.00,
  12,
  'Layer-7 stateful inspection firewall with IPSec VPN hardware acceleration',
  'admin',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO products (id, name, sku, category, price, stock, description, created_by, created_at, updated_at)
VALUES (
  'prod-00000000-0000-0000-0000-000000000002',
  'HSM Cryptographic Key Accelerator',
  'CRYPTO-HSM-9',
  'Security Hardware',
  899.50,
  45,
  'FIPS 140-2 Level 3 certified hardware security module for RSA/ECC key storage',
  'admin',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO products (id, name, sku, category, price, stock, description, created_by, created_at, updated_at)
VALUES (
  'prod-00000000-0000-0000-0000-000000000003',
  'Audit Vault Immutable Storage Array',
  'STRG-VLT-04',
  'Infrastructure',
  4200.00,
  8,
  'WORM compliant high-density NVMe storage array for audit logs retention',
  'admin',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO products (id, name, sku, category, price, stock, description, created_by, created_at, updated_at)
VALUES (
  'prod-00000000-0000-0000-0000-000000000004',
  'Zero-Trust Secure Access License (100 Seat)',
  'LIC-ZTG-100',
  'Software Licenses',
  350.00,
  250,
  'Continuous identity verification client licence with telemetry auditing',
  'admin',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO products (id, name, sku, category, price, stock, description, created_by, created_at, updated_at)
VALUES (
  'prod-00000000-0000-0000-0000-000000000005',
  'Managed Bastion Host Gateway',
  'CLOUD-BST-22',
  'Cloud Infrastructure',
  680.00,
  20,
  'Audited SSH/RDP jump server with keystroke session recording',
  'admin',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- Compliance & Operational Tasks Seed
-- ----------------------------------------------------------------------------
INSERT OR IGNORE INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date, created_at, updated_at)
VALUES (
  'task-00000000-0000-0000-0000-000000000001',
  'Review Q3 PCI-DSS compliance requirements',
  'Audit requirement 10.2: verify automated audit trails are enabled and reviewed for all system components.',
  'high',
  'in_progress',
  'alice',
  'admin',
  '2026-11-15',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date, created_at, updated_at)
VALUES (
  'task-00000000-0000-0000-0000-000000000002',
  'Conduct quarterly cryptographic key rotation',
  'Rotate HSM master encryption keys and record JTI authorization trace in audit vault.',
  'urgent',
  'pending',
  'alice',
  'admin',
  '2026-10-30',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date, created_at, updated_at)
VALUES (
  'task-00000000-0000-0000-0000-000000000003',
  'Update customer disaster recovery runbooks',
  'Document DB backup restoration procedure from cold storage and test hash validation.',
  'medium',
  'completed',
  'bob',
  'admin',
  '2026-10-20',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date, created_at, updated_at)
VALUES (
  'task-00000000-0000-0000-0000-000000000004',
  'Inspect SIEM forwarding rules for audit.db',
  'Ensure syslog daemon mirrors all SQL trigger alerts to central security operations center.',
  'high',
  'completed',
  'admin',
  'admin',
  '2026-10-22',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);
