-- ============================================================================
-- Migration: 001_sqlserver_init_schema.sql
-- Target Database: Microsoft SQL Server (SSMS) / Azure SQL Database
-- Database Models Supported:
--   1. Distributed 3-Database Architecture:
--      - `AuditPro_Auth`
--      - `AuditPro_Business`
--      - `AuditPro_Audit`
--   2. Unified Enterprise Data Warehouse:
--      - `AuditProDB`
-- Compliance Scope: SOC 2 Type II, HIPAA §164.312, PCI-DSS 4.0 Requirement 10
-- Description:
--   Creates complete T-SQL schemas, relational constraints, performance indexes,
--   and SQL Server INSTEAD OF immutability triggers mirroring SQLite WORM policy.
-- ============================================================================

-- ============================================================================
-- PART 1: 3-DATABASE ISOLATED ARCHITECTURE
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Database 1: AuditPro_Auth (Identity & Access Control)
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'AuditPro_Auth')
BEGIN
  PRINT '[Migration] Creating database AuditPro_Auth...';
  CREATE DATABASE AuditPro_Auth;
END
GO

USE AuditPro_Auth;
GO

-- Table: users (Identity credentials with bcrypt hash)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'users')
BEGIN
  PRINT '[Migration] Creating table AuditPro_Auth.dbo.users...';
  CREATE TABLE users (
    -- id: Unique RFC 4122 v4 UUID string identifier
    id NVARCHAR(100) NOT NULL PRIMARY KEY,

    -- username: Unique user login identifier (case-insensitive in standard SQL Server collation)
    username NVARCHAR(100) NOT NULL CONSTRAINT UQ_auth_users_username UNIQUE,

    -- password_hash: Bcrypt salted password hash
    password_hash NVARCHAR(255) NOT NULL,

    -- role: RBAC role constrained to admin, auditor, or user
    role NVARCHAR(50) NOT NULL CONSTRAINT CK_auth_users_role CHECK (role IN ('admin', 'auditor', 'user')),

    -- full_name: Full display and audit name
    full_name NVARCHAR(200) NOT NULL,

    -- created_at: High-precision UTC creation timestamp
    created_at DATETIME2 NOT NULL CONSTRAINT DF_auth_users_created DEFAULT SYSUTCDATETIME(),

    -- updated_at: High-precision UTC update timestamp
    updated_at DATETIME2 NOT NULL CONSTRAINT DF_auth_users_updated DEFAULT SYSUTCDATETIME()
  );
END
GO

-- Table: refresh_tokens (Rotated cryptographic token store)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'refresh_tokens')
BEGIN
  PRINT '[Migration] Creating table AuditPro_Auth.dbo.refresh_tokens...';
  CREATE TABLE refresh_tokens (
    -- id: UUID primary key
    id NVARCHAR(100) NOT NULL PRIMARY KEY,

    -- user_id: Foreign key linking to users(id)
    user_id NVARCHAR(100) NOT NULL,

    -- token_hash: SHA-256 / bcrypt hash of token string
    token_hash NVARCHAR(255) NOT NULL,

    -- jti: JWT ID claim for revocation detection
    jti NVARCHAR(100) NOT NULL,

    -- expires_at: Absolute expiration timestamp
    expires_at DATETIME2 NOT NULL,

    -- created_at: Token issuance timestamp
    created_at DATETIME2 NOT NULL CONSTRAINT DF_auth_refresh_created DEFAULT SYSUTCDATETIME(),

    -- revoked: Active (0) or Revoked (1)
    revoked INT NOT NULL CONSTRAINT DF_auth_refresh_revoked DEFAULT 0,

    -- replaced_by_token: Hash of rotated child token
    replaced_by_token NVARCHAR(255) NULL,

    -- Cascading foreign key deletes tokens if user record is removed
    CONSTRAINT FK_auth_refresh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE NONCLUSTERED INDEX idx_ssms_refresh_token_hash ON refresh_tokens(token_hash);
  CREATE NONCLUSTERED INDEX idx_ssms_refresh_user_id ON refresh_tokens(user_id);
END
GO

-- ----------------------------------------------------------------------------
-- Database 2: AuditPro_Business (Products Catalog & Task Workflows)
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'AuditPro_Business')
BEGIN
  PRINT '[Migration] Creating database AuditPro_Business...';
  CREATE DATABASE AuditPro_Business;
END
GO

USE AuditPro_Business;
GO

-- Table: products (Hardware, licenses, and inventory)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'products')
BEGIN
  PRINT '[Migration] Creating table AuditPro_Business.dbo.products...';
  CREATE TABLE products (
    -- id: UUID primary key
    id NVARCHAR(100) NOT NULL PRIMARY KEY,

    -- name: Catalog product name
    name NVARCHAR(255) NOT NULL,

    -- sku: Unique stock keeping unit
    sku NVARCHAR(100) NOT NULL CONSTRAINT UQ_biz_products_sku UNIQUE,

    -- category: Product category classification
    category NVARCHAR(100) NOT NULL,

    -- price: Monetary amount with 2 decimal precision
    price DECIMAL(18, 2) NOT NULL,

    -- stock: Current inventory count
    stock INT NOT NULL,

    -- description: Detailed specifications
    description NVARCHAR(MAX) NULL,

    -- created_by: Creator username
    created_by NVARCHAR(100) NOT NULL,

    -- created_at: Creation timestamp
    created_at DATETIME2 NOT NULL CONSTRAINT DF_biz_products_created DEFAULT SYSUTCDATETIME(),

    -- updated_at: Modification timestamp
    updated_at DATETIME2 NOT NULL CONSTRAINT DF_biz_products_updated DEFAULT SYSUTCDATETIME()
  );

  CREATE NONCLUSTERED INDEX idx_ssms_products_category ON products(category);
  CREATE NONCLUSTERED INDEX idx_ssms_products_sku ON products(sku);
END
GO

-- Table: tasks (Governance, compliance, and operational tasks)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'tasks')
BEGIN
  PRINT '[Migration] Creating table AuditPro_Business.dbo.tasks...';
  CREATE TABLE tasks (
    -- id: UUID primary key
    id NVARCHAR(100) NOT NULL PRIMARY KEY,

    -- title: Task summary
    title NVARCHAR(255) NOT NULL,

    -- description: Scope of task work
    description NVARCHAR(MAX) NULL,

    -- priority: Constrained to low, medium, high, urgent
    priority NVARCHAR(50) NOT NULL CONSTRAINT CK_biz_tasks_priority CHECK (priority IN ('low', 'medium', 'high', 'urgent')),

    -- status: Constrained to pending, in_progress, completed, archived
    status NVARCHAR(50) NOT NULL CONSTRAINT CK_biz_tasks_status CHECK (status IN ('pending', 'in_progress', 'completed', 'archived')),

    -- assigned_to: Assignee username
    assigned_to NVARCHAR(100) NOT NULL,

    -- created_by: Creator username
    created_by NVARCHAR(100) NOT NULL,

    -- due_date: ISO date string (YYYY-MM-DD)
    due_date NVARCHAR(50) NULL,

    -- created_at: Creation timestamp
    created_at DATETIME2 NOT NULL CONSTRAINT DF_biz_tasks_created DEFAULT SYSUTCDATETIME(),

    -- updated_at: Last modification timestamp
    updated_at DATETIME2 NOT NULL CONSTRAINT DF_biz_tasks_updated DEFAULT SYSUTCDATETIME()
  );

  CREATE NONCLUSTERED INDEX idx_ssms_tasks_assigned_to ON tasks(assigned_to);
  CREATE NONCLUSTERED INDEX idx_ssms_tasks_status ON tasks(status);
END
GO

-- ----------------------------------------------------------------------------
-- Database 3: AuditPro_Audit (Immutable Forensics Vault)
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'AuditPro_Audit')
BEGIN
  PRINT '[Migration] Creating database AuditPro_Audit...';
  CREATE DATABASE AuditPro_Audit;
END
GO

USE AuditPro_Audit;
GO

-- Table: audit_logs (Forensics event log)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'audit_logs')
BEGIN
  PRINT '[Migration] Creating table AuditPro_Audit.dbo.audit_logs...';
  CREATE TABLE audit_logs (
    -- id: Identity primary key
    id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,

    -- timestamp: Event occurrence timestamp
    timestamp DATETIME2 NOT NULL CONSTRAINT DF_audit_logs_timestamp DEFAULT SYSUTCDATETIME(),

    -- event: Event code
    event NVARCHAR(100) NOT NULL,

    -- user_id: Actor UUID
    user_id NVARCHAR(100) NULL,

    -- username: Actor username handle
    username NVARCHAR(100) NULL,

    -- role: Actor role tier
    role NVARCHAR(50) NULL,

    -- ip_address: Originating network IP
    ip_address NVARCHAR(50) NULL,

    -- action: Detailed human-readable log message
    action NVARCHAR(MAX) NOT NULL,

    -- entity_id: Target entity identifier
    entity_id NVARCHAR(100) NULL,

    -- status: Execution outcome (SUCCESS, FAILED, BLOCKED)
    status NVARCHAR(50) NOT NULL CONSTRAINT DF_audit_logs_status DEFAULT 'SUCCESS'
  );

  CREATE NONCLUSTERED INDEX idx_ssms_audit_logs_event ON audit_logs(event);
  CREATE NONCLUSTERED INDEX idx_ssms_audit_logs_username ON audit_logs(username);
  CREATE NONCLUSTERED INDEX idx_ssms_audit_logs_timestamp ON audit_logs(timestamp);
END
GO

-- Table: jwt_events (Cryptographic token activity telemetry)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'jwt_events')
BEGIN
  PRINT '[Migration] Creating table AuditPro_Audit.dbo.jwt_events...';
  CREATE TABLE jwt_events (
    id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    timestamp DATETIME2 NOT NULL CONSTRAINT DF_jwt_events_timestamp DEFAULT SYSUTCDATETIME(),
    jti NVARCHAR(100) NOT NULL,
    event_type NVARCHAR(50) NOT NULL,
    user_id NVARCHAR(100) NULL,
    username NVARCHAR(100) NULL,
    endpoint NVARCHAR(255) NULL,
    ip_address NVARCHAR(50) NULL,
    user_agent NVARCHAR(MAX) NULL,
    details NVARCHAR(MAX) NULL
  );

  CREATE NONCLUSTERED INDEX idx_ssms_jwt_events_jti ON jwt_events(jti);
END
GO

-- Table: user_sessions (User session footprints and dwell durations)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'user_sessions')
BEGIN
  PRINT '[Migration] Creating table AuditPro_Audit.dbo.user_sessions...';
  CREATE TABLE user_sessions (
    id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    jti NVARCHAR(100) NOT NULL CONSTRAINT UQ_audit_sessions_jti UNIQUE,
    user_id NVARCHAR(100) NULL,
    username NVARCHAR(100) NOT NULL,
    role NVARCHAR(50) NULL,
    ip_address NVARCHAR(50) NULL,
    user_agent NVARCHAR(MAX) NULL,
    login_time DATETIME2 NOT NULL CONSTRAINT DF_audit_sessions_login DEFAULT SYSUTCDATETIME(),
    last_active DATETIME2 NOT NULL CONSTRAINT DF_audit_sessions_active DEFAULT SYSUTCDATETIME(),
    logout_time DATETIME2 NULL,
    duration_seconds INT NOT NULL CONSTRAINT DF_audit_sessions_dur DEFAULT 0,
    formatted_duration NVARCHAR(50) NOT NULL CONSTRAINT DF_audit_sessions_dur_fmt DEFAULT '0s',
    status NVARCHAR(50) NOT NULL CONSTRAINT DF_audit_sessions_status DEFAULT 'ACTIVE',
    last_view NVARCHAR(200) NOT NULL CONSTRAINT DF_audit_sessions_view DEFAULT 'Dashboard',
    total_actions INT NOT NULL CONSTRAINT DF_audit_sessions_actions DEFAULT 0,
    created_at DATETIME2 NOT NULL CONSTRAINT DF_audit_sessions_created DEFAULT SYSUTCDATETIME()
  );

  CREATE NONCLUSTERED INDEX idx_ssms_user_sessions_username ON user_sessions(username);
  CREATE NONCLUSTERED INDEX idx_ssms_user_sessions_jti ON user_sessions(jti);
END
GO

-- ----------------------------------------------------------------------------
-- SQL SERVER IMMUTABILITY TRIGGERS (AuditPro_Audit)
-- Replicates SQLite RAISE(ABORT) behavior using T-SQL THROW in INSTEAD OF triggers.
-- Prevents unauthorized UPDATE or DELETE attacks in SQL Server / SSMS.
-- ----------------------------------------------------------------------------
IF EXISTS (SELECT * FROM sys.triggers WHERE name = 'trg_audit_logs_prevent_update')
  DROP TRIGGER trg_audit_logs_prevent_update;
GO
CREATE TRIGGER trg_audit_logs_prevent_update
ON audit_logs
INSTEAD OF UPDATE
AS
BEGIN
  SET NOCOUNT ON;
  THROW 50001, 'Audit logs are immutable: UPDATE operations are strictly prohibited by compliance policy.', 1;
END
GO

IF EXISTS (SELECT * FROM sys.triggers WHERE name = 'trg_audit_logs_prevent_delete')
  DROP TRIGGER trg_audit_logs_prevent_delete;
GO
CREATE TRIGGER trg_audit_logs_prevent_delete
ON audit_logs
INSTEAD OF DELETE
AS
BEGIN
  SET NOCOUNT ON;
  THROW 50002, 'Audit logs are immutable: DELETE operations are strictly prohibited by compliance policy.', 1;
END
GO

IF EXISTS (SELECT * FROM sys.triggers WHERE name = 'trg_jwt_events_prevent_update')
  DROP TRIGGER trg_jwt_events_prevent_update;
GO
CREATE TRIGGER trg_jwt_events_prevent_update
ON jwt_events
INSTEAD OF UPDATE
AS
BEGIN
  SET NOCOUNT ON;
  THROW 50003, 'JWT events log is immutable: UPDATE operations are strictly prohibited.', 1;
END
GO

IF EXISTS (SELECT * FROM sys.triggers WHERE name = 'trg_jwt_events_prevent_delete')
  DROP TRIGGER trg_jwt_events_prevent_delete;
GO
CREATE TRIGGER trg_jwt_events_prevent_delete
ON jwt_events
INSTEAD OF DELETE
AS
BEGIN
  SET NOCOUNT ON;
  THROW 50004, 'JWT events log is immutable: DELETE operations are strictly prohibited.', 1;
END
GO

IF EXISTS (SELECT * FROM sys.triggers WHERE name = 'trg_user_sessions_prevent_delete')
  DROP TRIGGER trg_user_sessions_prevent_delete;
GO
CREATE TRIGGER trg_user_sessions_prevent_delete
ON user_sessions
INSTEAD OF DELETE
AS
BEGIN
  SET NOCOUNT ON;
  THROW 50005, 'User session history is immutable: DELETE operations are strictly prohibited.', 1;
END
GO


-- ============================================================================
-- PART 2: UNIFIED ENTERPRISE DATABASE (AuditProDB)
-- Houses all tables in a single SQL Server database for unified reporting.
-- ============================================================================
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'AuditProDB')
BEGIN
  PRINT '[Migration] Creating database AuditProDB...';
  CREATE DATABASE AuditProDB;
END
GO

USE AuditProDB;
GO

-- Users
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'users')
BEGIN
  CREATE TABLE users (
    id NVARCHAR(100) NOT NULL PRIMARY KEY,
    username NVARCHAR(100) NOT NULL CONSTRAINT UQ_unified_users_username UNIQUE,
    password_hash NVARCHAR(255) NOT NULL,
    role NVARCHAR(50) NOT NULL CONSTRAINT CK_unified_users_role CHECK (role IN ('admin', 'auditor', 'user')),
    full_name NVARCHAR(200) NOT NULL,
    created_at DATETIME2 NOT NULL CONSTRAINT DF_unified_users_created DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL CONSTRAINT DF_unified_users_updated DEFAULT SYSUTCDATETIME()
  );
END
GO

-- Refresh Tokens
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'refresh_tokens')
BEGIN
  CREATE TABLE refresh_tokens (
    id NVARCHAR(100) NOT NULL PRIMARY KEY,
    user_id NVARCHAR(100) NOT NULL,
    token_hash NVARCHAR(255) NOT NULL,
    jti NVARCHAR(100) NOT NULL,
    expires_at DATETIME2 NOT NULL,
    created_at DATETIME2 NOT NULL CONSTRAINT DF_unified_refresh_created DEFAULT SYSUTCDATETIME(),
    revoked INT NOT NULL CONSTRAINT DF_unified_refresh_revoked DEFAULT 0,
    replaced_by_token NVARCHAR(255) NULL,
    CONSTRAINT FK_unified_refresh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
END
GO

-- Products
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'products')
BEGIN
  CREATE TABLE products (
    id NVARCHAR(100) NOT NULL PRIMARY KEY,
    name NVARCHAR(255) NOT NULL,
    sku NVARCHAR(100) NOT NULL CONSTRAINT UQ_unified_products_sku UNIQUE,
    category NVARCHAR(100) NOT NULL,
    price DECIMAL(18, 2) NOT NULL,
    stock INT NOT NULL,
    description NVARCHAR(MAX) NULL,
    created_by NVARCHAR(100) NOT NULL,
    created_at DATETIME2 NOT NULL CONSTRAINT DF_unified_products_created DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL CONSTRAINT DF_unified_products_updated DEFAULT SYSUTCDATETIME()
  );
END
GO

-- Tasks
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'tasks')
BEGIN
  CREATE TABLE tasks (
    id NVARCHAR(100) NOT NULL PRIMARY KEY,
    title NVARCHAR(255) NOT NULL,
    description NVARCHAR(MAX) NULL,
    priority NVARCHAR(50) NOT NULL CONSTRAINT CK_unified_tasks_priority CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
    status NVARCHAR(50) NOT NULL CONSTRAINT CK_unified_tasks_status CHECK (status IN ('pending', 'in_progress', 'completed', 'archived')),
    assigned_to NVARCHAR(100) NOT NULL,
    created_by NVARCHAR(100) NOT NULL,
    due_date NVARCHAR(50) NULL,
    created_at DATETIME2 NOT NULL CONSTRAINT DF_unified_tasks_created DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL CONSTRAINT DF_unified_tasks_updated DEFAULT SYSUTCDATETIME()
  );
END
GO

-- Audit Logs
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'audit_logs')
BEGIN
  CREATE TABLE audit_logs (
    id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    timestamp DATETIME2 NOT NULL CONSTRAINT DF_unified_audit_timestamp DEFAULT SYSUTCDATETIME(),
    event NVARCHAR(100) NOT NULL,
    user_id NVARCHAR(100) NULL,
    username NVARCHAR(100) NULL,
    role NVARCHAR(50) NULL,
    ip_address NVARCHAR(50) NULL,
    action NVARCHAR(MAX) NOT NULL,
    entity_id NVARCHAR(100) NULL,
    status NVARCHAR(50) NOT NULL CONSTRAINT DF_unified_audit_status DEFAULT 'SUCCESS'
  );

  CREATE NONCLUSTERED INDEX idx_unified_audit_logs_event ON audit_logs(event);
  CREATE NONCLUSTERED INDEX idx_unified_audit_logs_timestamp ON audit_logs(timestamp);
END
GO

-- User Sessions
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'user_sessions')
BEGIN
  CREATE TABLE user_sessions (
    id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    jti NVARCHAR(100) NOT NULL CONSTRAINT UQ_unified_sessions_jti UNIQUE,
    user_id NVARCHAR(100) NULL,
    username NVARCHAR(100) NOT NULL,
    role NVARCHAR(50) NULL,
    ip_address NVARCHAR(50) NULL,
    user_agent NVARCHAR(MAX) NULL,
    login_time DATETIME2 NOT NULL CONSTRAINT DF_unified_sessions_login DEFAULT SYSUTCDATETIME(),
    last_active DATETIME2 NOT NULL CONSTRAINT DF_unified_sessions_active DEFAULT SYSUTCDATETIME(),
    logout_time DATETIME2 NULL,
    duration_seconds INT NOT NULL CONSTRAINT DF_unified_sessions_dur DEFAULT 0,
    formatted_duration NVARCHAR(50) NOT NULL CONSTRAINT DF_unified_sessions_dur_fmt DEFAULT '0s',
    status NVARCHAR(50) NOT NULL CONSTRAINT DF_unified_sessions_status DEFAULT 'ACTIVE',
    last_view NVARCHAR(200) NOT NULL CONSTRAINT DF_unified_sessions_view DEFAULT 'Dashboard',
    total_actions INT NOT NULL CONSTRAINT DF_unified_sessions_actions DEFAULT 0,
    created_at DATETIME2 NOT NULL CONSTRAINT DF_unified_sessions_created DEFAULT SYSUTCDATETIME()
  );

  CREATE NONCLUSTERED INDEX idx_unified_sessions_username ON user_sessions(username);
  CREATE NONCLUSTERED INDEX idx_unified_sessions_jti ON user_sessions(jti);
END
GO

-- Unified Database Immutability Triggers
IF EXISTS (SELECT * FROM sys.triggers WHERE name = 'trg_unified_audit_logs_prevent_update')
  DROP TRIGGER trg_unified_audit_logs_prevent_update;
GO
CREATE TRIGGER trg_unified_audit_logs_prevent_update
ON audit_logs
INSTEAD OF UPDATE
AS
BEGIN
  SET NOCOUNT ON;
  THROW 50011, 'AuditProDB: Audit logs are immutable. UPDATE rejected.', 1;
END
GO

IF EXISTS (SELECT * FROM sys.triggers WHERE name = 'trg_unified_audit_logs_prevent_delete')
  DROP TRIGGER trg_unified_audit_logs_prevent_delete;
GO
CREATE TRIGGER trg_unified_audit_logs_prevent_delete
ON audit_logs
INSTEAD OF DELETE
AS
BEGIN
  SET NOCOUNT ON;
  THROW 50012, 'AuditProDB: Audit logs are immutable. DELETE rejected.', 1;
END
GO

PRINT '========================================================================';
PRINT '✅ SQL Server / SSMS AuditPro Migration Completed Successfully!';
PRINT '========================================================================';
GO
