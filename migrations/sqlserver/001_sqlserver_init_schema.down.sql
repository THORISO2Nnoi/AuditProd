-- ============================================================================
-- Migration Rollback: 001_sqlserver_init_schema.down.sql
-- Target Database: Microsoft SQL Server (SSMS)
-- Purpose: Teardown AuditPro SQL Server databases and objects
-- Caution: Running this permanently deletes all SQL Server replica databases
--          (AuditPro_Auth, AuditPro_Business, AuditPro_Audit, AuditProDB).
-- ============================================================================

USE master;
GO

-- Terminate active connections and drop unified AuditProDB
IF EXISTS (SELECT * FROM sys.databases WHERE name = 'AuditProDB')
BEGIN
  PRINT '[Rollback] Dropping database AuditProDB...';
  ALTER DATABASE AuditProDB SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
  DROP DATABASE AuditProDB;
END
GO

-- Terminate active connections and drop AuditPro_Audit
IF EXISTS (SELECT * FROM sys.databases WHERE name = 'AuditPro_Audit')
BEGIN
  PRINT '[Rollback] Dropping database AuditPro_Audit...';
  ALTER DATABASE AuditPro_Audit SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
  DROP DATABASE AuditPro_Audit;
END
GO

-- Terminate active connections and drop AuditPro_Business
IF EXISTS (SELECT * FROM sys.databases WHERE name = 'AuditPro_Business')
BEGIN
  PRINT '[Rollback] Dropping database AuditPro_Business...';
  ALTER DATABASE AuditPro_Business SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
  DROP DATABASE AuditPro_Business;
END
GO

-- Terminate active connections and drop AuditPro_Auth
IF EXISTS (SELECT * FROM sys.databases WHERE name = 'AuditPro_Auth')
BEGIN
  PRINT '[Rollback] Dropping database AuditPro_Auth...';
  ALTER DATABASE AuditPro_Auth SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
  DROP DATABASE AuditPro_Auth;
END
GO

PRINT '========================================================================';
PRINT '✅ SQL Server / SSMS Rollback Completed Successfully!';
PRINT '========================================================================';
GO
