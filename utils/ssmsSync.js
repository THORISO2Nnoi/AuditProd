const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const Database = require('better-sqlite3');

const auditDbPath = path.join(__dirname, '..', 'db', 'audit.db');
const authDbPath = path.join(__dirname, '..', 'db', 'auth.db');
const businessDbPath = path.join(__dirname, '..', 'db', 'business.db');
const syncSqlPath = path.join(__dirname, '..', 'sync.sql');

let isSyncing = false;
let pendingSync = false;
let lastSyncTime = null;
let lastSyncStatus = 'IDLE';
let lastSyncStats = {};

function esc(val) {
  if (val === null || val === undefined) return 'NULL';
  const s = String(val).replace(/'/g, "''");
  return `N'${s}'`;
}

/**
 * Generate full SQL script that replicates all SQLite databases
 * to both the 3-Database setup (AuditPro_Audit, AuditPro_Auth, AuditPro_Business)
 * and the unified AuditProDB in SQL Server / SSMS.
 */
function generateSyncSql() {
  const auditDb = new Database(auditDbPath, { readonly: true });
  const authDb = new Database(authDbPath, { readonly: true });
  const bizDb = new Database(businessDbPath, { readonly: true });

  const statements = [
    "-- ====================================================",
    "-- AUDITPRO AUTOMATED SSMS / SQL SERVER SYNCHRONIZATION",
    `-- Generated At: ${new Date().toISOString()}`,
    "-- ====================================================",
    ""
  ];

  // 1. Ensure user_sessions table exists in AuditPro_Audit and AuditProDB
  statements.push(
    "USE AuditPro_Audit;",
    "IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'user_sessions')",
    "BEGIN",
    "  CREATE TABLE user_sessions (",
    "    id INT IDENTITY(1,1) PRIMARY KEY,",
    "    jti NVARCHAR(100) NOT NULL,",
    "    user_id NVARCHAR(100) NULL,",
    "    username NVARCHAR(100) NOT NULL,",
    "    role NVARCHAR(50) NULL,",
    "    ip_address NVARCHAR(50) NULL,",
    "    user_agent NVARCHAR(MAX) NULL,",
    "    login_time DATETIME2 DEFAULT GETDATE(),",
    "    last_active DATETIME2 DEFAULT GETDATE(),",
    "    logout_time DATETIME2 NULL,",
    "    duration_seconds INT DEFAULT 0,",
    "    formatted_duration NVARCHAR(50) DEFAULT '0s',",
    "    status NVARCHAR(50) DEFAULT 'ACTIVE',",
    "    last_view NVARCHAR(200) DEFAULT 'Dashboard',",
    "    total_actions INT DEFAULT 0,",
    "    created_at DATETIME2 DEFAULT GETDATE()",
    "  );",
    "END",
    "GO"
  );

  // Sync AuditPro_Audit: audit_logs
  const auditLogs = auditDb.prepare('SELECT * FROM audit_logs ORDER BY id ASC').all();
  statements.push(
    "USE AuditPro_Audit;",
    "TRUNCATE TABLE audit_logs;",
    "SET IDENTITY_INSERT audit_logs ON;"
  );
  for (const row of auditLogs) {
    statements.push(
      `INSERT INTO audit_logs (id, timestamp, event, user_id, username, role, ip_address, action, entity_id, status) ` +
      `VALUES (${row.id}, ${esc(row.timestamp)}, ${esc(row.event)}, ${esc(row.user_id)}, ${esc(row.username)}, ${esc(row.role)}, ${esc(row.ip_address)}, ${esc(row.action)}, ${esc(row.entity_id)}, ${esc(row.status)});`
    );
  }
  statements.push("SET IDENTITY_INSERT audit_logs OFF;", "GO");

  // Sync AuditPro_Audit: user_sessions
  const userSessions = auditDb.prepare('SELECT * FROM user_sessions ORDER BY id ASC').all();
  statements.push(
    "USE AuditPro_Audit;",
    "TRUNCATE TABLE user_sessions;",
    "SET IDENTITY_INSERT user_sessions ON;"
  );
  for (const s of userSessions) {
    const mins = Math.floor((s.duration_seconds || 0) / 60);
    const secs = (s.duration_seconds || 0) % 60;
    const formatted = s.formatted_duration || (mins > 0 ? `${mins}m ${secs}s` : `${secs}s`);
    statements.push(
      `INSERT INTO user_sessions (id, jti, user_id, username, role, ip_address, user_agent, login_time, last_active, logout_time, duration_seconds, formatted_duration, status, last_view, total_actions, created_at) ` +
      `VALUES (${s.id}, ${esc(s.jti)}, ${esc(s.user_id)}, ${esc(s.username)}, ${esc(s.role)}, ${esc(s.ip_address)}, ${esc(s.user_agent)}, ${esc(s.login_time)}, ${esc(s.last_active)}, ${esc(s.logout_time)}, ${s.duration_seconds || 0}, ${esc(formatted)}, ${esc(s.status || 'ACTIVE')}, ${esc(s.last_view || 'Dashboard')}, ${s.total_actions || 0}, ${esc(s.created_at)});`
    );
  }
  statements.push("SET IDENTITY_INSERT user_sessions OFF;", "GO");

  // Sync AuditPro_Audit: jwt_events
  const jwtEvents = auditDb.prepare('SELECT * FROM jwt_events ORDER BY id ASC').all();
  statements.push(
    "USE AuditPro_Audit;",
    "TRUNCATE TABLE jwt_events;",
    "SET IDENTITY_INSERT jwt_events ON;"
  );
  for (const j of jwtEvents) {
    statements.push(
      `INSERT INTO jwt_events (id, timestamp, jti, event_type, user_id, username, endpoint, ip_address, user_agent, details) ` +
      `VALUES (${j.id}, ${esc(j.timestamp)}, ${esc(j.jti)}, ${esc(j.event_type)}, ${esc(j.user_id)}, ${esc(j.username)}, ${esc(j.endpoint)}, ${esc(j.ip_address)}, ${esc(j.user_agent)}, ${esc(j.details)});`
    );
  }
  statements.push("SET IDENTITY_INSERT jwt_events OFF;", "GO");

  // Sync AuditPro_Business: products
  const products = bizDb.prepare('SELECT * FROM products ORDER BY created_at ASC').all();
  statements.push(
    "USE AuditPro_Business;",
    "TRUNCATE TABLE products;"
  );
  for (const p of products) {
    statements.push(
      `INSERT INTO products (id, name, sku, category, price, stock, description, created_by, created_at, updated_at) ` +
      `VALUES (${esc(p.id)}, ${esc(p.name)}, ${esc(p.sku)}, ${esc(p.category)}, ${Number(p.price)}, ${Number(p.stock)}, ${esc(p.description)}, ${esc(p.created_by)}, ${esc(p.created_at)}, ${esc(p.updated_at)});`
    );
  }
  statements.push("GO");

  // Sync AuditPro_Business: tasks
  const tasks = bizDb.prepare('SELECT * FROM tasks ORDER BY created_at ASC').all();
  statements.push(
    "USE AuditPro_Business;",
    "TRUNCATE TABLE tasks;"
  );
  for (const t of tasks) {
    statements.push(
      `INSERT INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date, created_at, updated_at) ` +
      `VALUES (${esc(t.id)}, ${esc(t.title)}, ${esc(t.description)}, ${esc(t.priority)}, ${esc(t.status)}, ${esc(t.assigned_to)}, ${esc(t.created_by)}, ${esc(t.due_date)}, ${esc(t.created_at)}, ${esc(t.updated_at)});`
    );
  }
  statements.push("GO");

  // Sync AuditPro_Auth: users
  const users = authDb.prepare('SELECT * FROM users ORDER BY created_at ASC').all();
  statements.push(
    "USE AuditPro_Auth;",
    "TRUNCATE TABLE users;"
  );
  for (const u of users) {
    statements.push(
      `INSERT INTO users (id, username, password_hash, role, full_name, created_at, updated_at) ` +
      `VALUES (${esc(u.id)}, ${esc(u.username)}, ${esc(u.password_hash)}, ${esc(u.role)}, ${esc(u.full_name)}, ${esc(u.created_at)}, ${esc(u.updated_at)});`
    );
  }
  statements.push("GO");

  // Sync AuditPro_Auth: refresh_tokens
  const tokens = authDb.prepare('SELECT * FROM refresh_tokens ORDER BY created_at ASC').all();
  statements.push(
    "USE AuditPro_Auth;",
    "TRUNCATE TABLE refresh_tokens;"
  );
  for (const tk of tokens) {
    statements.push(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, jti, expires_at, created_at, revoked, replaced_by_token) ` +
      `VALUES (${esc(tk.id)}, ${esc(tk.user_id)}, ${esc(tk.token_hash)}, ${esc(tk.jti)}, ${esc(tk.expires_at)}, ${esc(tk.created_at)}, ${tk.revoked || 0}, ${esc(tk.replaced_by_token)});`
    );
  }
  statements.push("GO");

  // Also Mirror all to AuditProDB (unified database) if present
  statements.push(
    "USE AuditProDB;",
    "TRUNCATE TABLE audit_logs;",
    "SET IDENTITY_INSERT audit_logs ON;"
  );
  for (const row of auditLogs) {
    statements.push(
      `INSERT INTO audit_logs (id, timestamp, event, user_id, username, role, ip_address, action, entity_id, status) ` +
      `VALUES (${row.id}, ${esc(row.timestamp)}, ${esc(row.event)}, ${esc(row.user_id)}, ${esc(row.username)}, ${esc(row.role)}, ${esc(row.ip_address)}, ${esc(row.action)}, ${esc(row.entity_id)}, ${esc(row.status)});`
    );
  }
  statements.push("SET IDENTITY_INSERT audit_logs OFF;", "GO");

  statements.push(
    "USE AuditProDB;",
    "TRUNCATE TABLE user_sessions;",
    "SET IDENTITY_INSERT user_sessions ON;"
  );
  for (const s of userSessions) {
    const mins = Math.floor((s.duration_seconds || 0) / 60);
    const secs = (s.duration_seconds || 0) % 60;
    const formatted = s.formatted_duration || (mins > 0 ? `${mins}m ${secs}s` : `${secs}s`);
    statements.push(
      `INSERT INTO user_sessions (id, jti, user_id, username, role, ip_address, user_agent, login_time, last_active, logout_time, duration_seconds, formatted_duration, status, last_view, total_actions, created_at) ` +
      `VALUES (${s.id}, ${esc(s.jti)}, ${esc(s.user_id)}, ${esc(s.username)}, ${esc(s.role)}, ${esc(s.ip_address)}, ${esc(s.user_agent)}, ${esc(s.login_time)}, ${esc(s.last_active)}, ${esc(s.logout_time)}, ${s.duration_seconds || 0}, ${esc(formatted)}, ${esc(s.status || 'ACTIVE')}, ${esc(s.last_view || 'Dashboard')}, ${s.total_actions || 0}, ${esc(s.created_at)});`
    );
  }
  statements.push("SET IDENTITY_INSERT user_sessions OFF;", "GO");

  statements.push(
    "USE AuditProDB;",
    "TRUNCATE TABLE tasks;"
  );
  for (const t of tasks) {
    statements.push(
      `INSERT INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date, created_at, updated_at) ` +
      `VALUES (${esc(t.id)}, ${esc(t.title)}, ${esc(t.description)}, ${esc(t.priority)}, ${esc(t.status)}, ${esc(t.assigned_to)}, ${esc(t.created_by)}, ${esc(t.due_date)}, ${esc(t.created_at)}, ${esc(t.updated_at)});`
    );
  }
  statements.push("GO");

  statements.push(
    "USE AuditProDB;",
    "TRUNCATE TABLE products;"
  );
  for (const p of products) {
    statements.push(
      `INSERT INTO products (id, name, sku, category, price, stock, description, created_by, created_at, updated_at) ` +
      `VALUES (${esc(p.id)}, ${esc(p.name)}, ${esc(p.sku)}, ${esc(p.category)}, ${Number(p.price)}, ${Number(p.stock)}, ${esc(p.description)}, ${esc(p.created_by)}, ${esc(p.created_at)}, ${esc(p.updated_at)});`
    );
  }
  statements.push("GO");

  statements.push(
    "USE AuditProDB;",
    "TRUNCATE TABLE users;"
  );
  for (const u of users) {
    statements.push(
      `INSERT INTO users (id, username, password_hash, role, full_name, created_at, updated_at) ` +
      `VALUES (${esc(u.id)}, ${esc(u.username)}, ${esc(u.password_hash)}, ${esc(u.role)}, ${esc(u.full_name)}, ${esc(u.created_at)}, ${esc(u.updated_at)});`
    );
  }
  statements.push("GO");

  // Close db handles
  auditDb.close();
  authDb.close();
  bizDb.close();

  const stats = {
    auditLogsCount: auditLogs.length,
    userSessionsCount: userSessions.length,
    jwtEventsCount: jwtEvents.length,
    tasksCount: tasks.length,
    productsCount: products.length,
    usersCount: users.length
  };

  return { sql: statements.join('\n'), stats };
}

/**
 * Execute sync to SSMS via sqlcmd
 */
function syncToSsms() {
  return new Promise((resolve) => {
    if (isSyncing) {
      pendingSync = true;
      return resolve({ success: true, queued: true });
    }

    isSyncing = true;
    try {
      const { sql, stats } = generateSyncSql();
      fs.writeFileSync(syncSqlPath, sql, 'utf8');

      const cmd = `sqlcmd -S localhost -i "${syncSqlPath}" -E`;
      exec(cmd, (err, stdout, stderr) => {
        isSyncing = false;
        if (err) {
          lastSyncStatus = 'ERROR';
          console.error('[SSMS Sync Engine] SQLCMD error:', err.message);
          resolve({ success: false, error: err.message, stderr });
        } else {
          lastSyncTime = new Date().toISOString();
          lastSyncStatus = 'IN_SYNC';
          lastSyncStats = stats;
          console.log(`[SSMS Sync Engine] ✅ Database synchronized with SSMS: ${stats.auditLogsCount} logs, ${stats.userSessionsCount} sessions, ${stats.tasksCount} tasks, ${stats.productsCount} products.`);
          resolve({ success: true, timestamp: lastSyncTime, stats });
        }

        if (pendingSync) {
          pendingSync = false;
          setTimeout(syncToSsms, 1000);
        }
      });
    } catch (err) {
      isSyncing = false;
      lastSyncStatus = 'ERROR';
      console.error('[SSMS Sync Engine] Execution error:', err.message);
      resolve({ success: false, error: err.message });
    }
  });
}

// Debounce helper for automatic live updates
let debounceTimer = null;
function triggerSyncDebounced(delay = 1500) {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    syncToSsms();
  }, delay);
}

module.exports = {
  syncToSsms,
  triggerSyncDebounced,
  getSyncStatus: () => ({
    status: lastSyncStatus,
    lastSyncTime,
    lastSyncStats
  })
};
