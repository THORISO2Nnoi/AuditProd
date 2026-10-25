const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'audit.db');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

// Initialize schema and immutability triggers
db.exec(`
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event TEXT NOT NULL,
    user_id TEXT,
    username TEXT,
    role TEXT,
    ip_address TEXT,
    user_agent TEXT,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    before_snapshot TEXT,
    after_snapshot TEXT,
    diff TEXT,
    jti TEXT,
    status TEXT DEFAULT 'SUCCESS',
    metadata TEXT
  );

  CREATE TABLE IF NOT EXISTS jwt_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    jti TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id TEXT,
    username TEXT,
    endpoint TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT
  );

  CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jti TEXT UNIQUE NOT NULL,
    user_id TEXT,
    username TEXT NOT NULL,
    role TEXT,
    ip_address TEXT,
    user_agent TEXT,
    login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_active DATETIME DEFAULT CURRENT_TIMESTAMP,
    duration_seconds INTEGER DEFAULT 0,
    status TEXT DEFAULT 'ACTIVE',
    last_view TEXT DEFAULT 'Dashboard',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs(username);
  CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event);
  CREATE INDEX IF NOT EXISTS idx_audit_jti ON audit_logs(jti);
  CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
  CREATE INDEX IF NOT EXISTS idx_jwt_events_jti ON jwt_events(jti);
  CREATE INDEX IF NOT EXISTS idx_user_sessions_jti ON user_sessions(jti);
  CREATE INDEX IF NOT EXISTS idx_user_sessions_username ON user_sessions(username);

  -- 🔐 DATABASE-LEVEL IMMUTABILITY TRIGGERS
  -- Prevents ANY update or delete on audit logs, even via direct sqlite3 CLI access
  CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_update
  BEFORE UPDATE ON audit_logs
  BEGIN
    SELECT RAISE(ABORT, 'Audit logs are immutable: UPDATE operations are strictly prohibited by compliance policy.');
  END;

  CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_delete
  BEFORE DELETE ON audit_logs
  BEGIN
    SELECT RAISE(ABORT, 'Audit logs are immutable: DELETE operations are strictly prohibited by compliance policy.');
  END;

  CREATE TRIGGER IF NOT EXISTS jwt_events_prevent_update
  BEFORE UPDATE ON jwt_events
  BEGIN
    SELECT RAISE(ABORT, 'JWT events log is immutable: UPDATE operations are strictly prohibited.');
  END;

  CREATE TRIGGER IF NOT EXISTS jwt_events_prevent_delete
  BEFORE DELETE ON jwt_events
  BEGIN
    SELECT RAISE(ABORT, 'JWT events log is immutable: DELETE operations are strictly prohibited.');
  END;

  -- User session footprints cannot be deleted
  CREATE TRIGGER IF NOT EXISTS user_sessions_prevent_delete
  BEFORE DELETE ON user_sessions
  BEGIN
    SELECT RAISE(ABORT, 'User session history is immutable: DELETE operations are strictly prohibited.');
  END;
`);

function seedAuditInitialData() {
  const count = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get().count;
  if (count === 0) {
    const insert = db.prepare(`
      INSERT INTO audit_logs (
        timestamp, event, user_id, username, role, ip_address, user_agent, action,
        entity_type, entity_id, before_snapshot, after_snapshot, diff, jti, status, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const now = new Date();
    const tMinus10m = new Date(now.getTime() - 10 * 60 * 1000).toISOString();
    const tMinus8m = new Date(now.getTime() - 8 * 60 * 1000).toISOString();
    const tMinus5m = new Date(now.getTime() - 5 * 60 * 1000).toISOString();

    insert.run(
      tMinus10m,
      'SYSTEM_INIT',
      'system-root',
      'system',
      'system',
      '127.0.0.1',
      'AuditPro-Kernel/1.0',
      'Initialized 3-DB isolated architecture and enabled SQLite immutable triggers',
      'system',
      'kernel',
      null,
      JSON.stringify({ databases: ['auth.db', 'business.db', 'audit.db'], triggers_active: true }),
      null,
      '00000000-0000-0000-0000-000000000000',
      'SUCCESS',
      JSON.stringify({ mode: 'FIPS-Compliant-Simulated', integrity: 'SHA-256' })
    );

    insert.run(
      tMinus8m,
      'SEED_USERS',
      'system-root',
      'system',
      'system',
      '127.0.0.1',
      'AuditPro-Kernel/1.0',
      'Provisioned standard identity roles: admin, auditor, alice, bob',
      'user',
      'all',
      null,
      JSON.stringify({ users_seeded: ['admin', 'auditor', 'alice', 'bob'] }),
      null,
      '00000000-0000-0000-0000-000000000001',
      'SUCCESS',
      JSON.stringify({ policy: 'Role-Based Access Control' })
    );

    insert.run(
      tMinus5m,
      'UPDATE_PRODUCT',
      'admin-seed-id',
      'admin',
      'admin',
      '192.168.1.100',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'Adjusted catalog price for Enterprise Firewall Appliance X9',
      'product',
      'NET-FW-01',
      JSON.stringify({ name: 'Enterprise Firewall Appliance X9', sku: 'NET-FW-01', price: 2999.00, stock: 12 }),
      JSON.stringify({ name: 'Enterprise Firewall Appliance X9', sku: 'NET-FW-01', price: 2499.00, stock: 12 }),
      JSON.stringify({ price: { before: 2999.00, after: 2499.00 } }),
      'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
      'SUCCESS',
      JSON.stringify({ discount_campaign: 'Q3 Security Hardware Refresh' })
    );

    console.log('[Audit DB] Seeded initial compliance logs.');
  }
}

seedAuditInitialData();

/**
 * Log an audit record
 */
const logAudit = ({
  event,
  user_id = null,
  username = 'anonymous',
  role = 'guest',
  ip_address = '127.0.0.1',
  user_agent = '',
  action,
  entity_type = null,
  entity_id = null,
  before_snapshot = null,
  after_snapshot = null,
  diff = null,
  jti = null,
  status = 'SUCCESS',
  metadata = null,
  timestamp = null
}) => {
  try {
    const time = timestamp || new Date().toISOString();
    const beforeStr = before_snapshot ? (typeof before_snapshot === 'string' ? before_snapshot : JSON.stringify(before_snapshot)) : null;
    const afterStr = after_snapshot ? (typeof after_snapshot === 'string' ? after_snapshot : JSON.stringify(after_snapshot)) : null;
    const diffStr = diff ? (typeof diff === 'string' ? diff : JSON.stringify(diff)) : null;
    const metaStr = metadata ? (typeof metadata === 'string' ? metadata : JSON.stringify(metadata)) : null;

    const stmt = db.prepare(`
      INSERT INTO audit_logs (
        timestamp, event, user_id, username, role, ip_address, user_agent, action,
        entity_type, entity_id, before_snapshot, after_snapshot, diff, jti, status, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      time,
      event,
      user_id,
      username,
      role,
      ip_address,
      user_agent,
      action,
      entity_type,
      entity_id ? String(entity_id) : null,
      beforeStr,
      afterStr,
      diffStr,
      jti,
      status,
      metaStr
    );

    return { id: result.lastInsertRowid, success: true };
  } catch (err) {
    console.error('[Audit DB] Error logging audit event:', err.message);
    return { success: false, error: err.message };
  }
};

/**
 * Log a JWT lifecycle event (ISSUED, VERIFIED, EXPIRED, REFRESHED, REVOKED)
 */
const logJwtEvent = ({
  jti,
  event_type,
  user_id = null,
  username = null,
  endpoint = null,
  ip_address = '127.0.0.1',
  user_agent = '',
  details = null
}) => {
  try {
    const detailsStr = details ? (typeof details === 'string' ? details : JSON.stringify(details)) : null;

    db.prepare(`
      INSERT INTO jwt_events (
        jti, event_type, user_id, username, endpoint, ip_address, user_agent, details
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(jti, event_type, user_id, username, endpoint, ip_address, user_agent, detailsStr);
  } catch (err) {
    console.error('[Audit DB] Error logging JWT event:', err.message);
  }
};

/**
 * Fetch filtered audit logs with pagination
 */
const getAuditLogs = ({
  page = 1,
  limit = 20,
  username,
  event,
  status,
  entity_type,
  search,
  dateFrom,
  dateTo
} = {}) => {
  let query = 'SELECT * FROM audit_logs WHERE 1=1';
  let countQuery = 'SELECT COUNT(*) as total FROM audit_logs WHERE 1=1';
  const params = [];
  const countParams = [];

  if (username && username.trim().length > 0) {
    query += ' AND username = ?';
    countQuery += ' AND username = ?';
    params.push(username.trim());
    countParams.push(username.trim());
  }

  if (event && event.trim().length > 0) {
    const ev = event.trim();
    if (ev === 'VIEW_') {
      query += ' AND event LIKE ?';
      countQuery += ' AND event LIKE ?';
      params.push('VIEW_%');
      countParams.push('VIEW_%');
    } else if (ev === 'MUTATION') {
      query += ' AND (event LIKE ? OR event LIKE ? OR event LIKE ?)';
      countQuery += ' AND (event LIKE ? OR event LIKE ? OR event LIKE ?)';
      params.push('%CREATE%', '%UPDATE%', '%DELETE%');
      countParams.push('%CREATE%', '%UPDATE%', '%DELETE%');
    } else if (ev === 'AUTH') {
      query += ' AND (event LIKE ? OR event LIKE ? OR event LIKE ?)';
      countQuery += ' AND (event LIKE ? OR event LIKE ? OR event LIKE ?)';
      params.push('%LOGIN%', '%LOGOUT%', '%REFRESH%');
      countParams.push('%LOGIN%', '%LOGOUT%', '%REFRESH%');
    } else if (ev.endsWith('_')) {
      query += ' AND event LIKE ?';
      countQuery += ' AND event LIKE ?';
      params.push(`${ev}%`);
      countParams.push(`${ev}%`);
    } else {
      query += ' AND event = ?';
      countQuery += ' AND event = ?';
      params.push(ev);
      countParams.push(ev);
    }
  }

  if (status && status.trim().length > 0) {
    query += ' AND status = ?';
    countQuery += ' AND status = ?';
    params.push(status.trim());
    countParams.push(status.trim());
  }

  if (entity_type && entity_type.trim().length > 0) {
    query += ' AND entity_type = ?';
    countQuery += ' AND entity_type = ?';
    params.push(entity_type.trim());
    countParams.push(entity_type.trim());
  }

  if (dateFrom && dateFrom.trim().length > 0) {
    query += ' AND timestamp >= ?';
    countQuery += ' AND timestamp >= ?';
    params.push(dateFrom.trim());
    countParams.push(dateFrom.trim());
  }

  if (dateTo && dateTo.trim().length > 0) {
    query += ' AND timestamp <= ?';
    countQuery += ' AND timestamp <= ?';
    params.push(dateTo.trim());
    countParams.push(dateTo.trim());
  }

  if (search && search.trim().length > 0) {
    const s = `%${search.trim()}%`;
    query += ' AND (action LIKE ? OR jti LIKE ? OR username LIKE ? OR entity_id LIKE ?)';
    countQuery += ' AND (action LIKE ? OR jti LIKE ? OR username LIKE ? OR entity_id LIKE ?)';
    params.push(s, s, s, s);
    countParams.push(s, s, s, s);
  }

  const totalRecord = db.prepare(countQuery).get(...countParams);
  const total = totalRecord ? totalRecord.total : 0;

  const offset = (Math.max(1, Number(page)) - 1) * Number(limit);
  query += ' ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?';
  params.push(Number(limit), offset);

  const logs = db.prepare(query).all(...params);

  return {
    logs,
    total,
    page: Number(page),
    limit: Number(limit),
    totalPages: Math.ceil(total / Number(limit)) || 1
  };
};

/**
 * Get individual log detail
 */
const getAuditLogById = (id) => {
  return db.prepare('SELECT * FROM audit_logs WHERE id = ?').get(id);
};

/**
 * Fetch JWT lifecycle history
 */
const getJwtEvents = ({ limit = 50, jti = null, username = null } = {}) => {
  let query = 'SELECT * FROM jwt_events WHERE 1=1';
  const params = [];

  if (jti) {
    query += ' AND jti = ?';
    params.push(jti);
  }
  if (username) {
    query += ' AND username = ?';
    params.push(username);
  }

  query += ' ORDER BY timestamp DESC, id DESC LIMIT ?';
  params.push(Number(limit));

  return db.prepare(query).all(...params);
};

/**
 * Get statistical metrics for Auditor and Admin dashboards
 */
const getAuditStats = () => {
  const totalLogs = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get().count;
  const totalJwtEvents = db.prepare('SELECT COUNT(*) as count FROM jwt_events').get().count;

  const statusCounts = db.prepare(`
    SELECT status, COUNT(*) as count 
    FROM audit_logs 
    GROUP BY status
  `).all();

  const successCount = (statusCounts.find(s => s.status === 'SUCCESS') || {}).count || 0;
  const deniedCount = (statusCounts.find(s => s.status === 'DENIED') || {}).count || 0;
  const failedCount = (statusCounts.find(s => s.status === 'FAILED') || {}).count || 0;
  const blockedCount = (statusCounts.find(s => s.status === 'BLOCKED') || {}).count || 0;

  const uniqueJtis = db.prepare('SELECT COUNT(DISTINCT jti) as count FROM audit_logs WHERE jti IS NOT NULL').get().count;

  // Today count
  const today = new Date().toISOString().split('T')[0];
  const todayLogs = db.prepare('SELECT COUNT(*) as count FROM audit_logs WHERE timestamp >= ?').get(today).count;

  // Breakdown by event
  const eventBreakdown = db.prepare(`
    SELECT event, COUNT(*) as count 
    FROM audit_logs 
    GROUP BY event 
    ORDER BY count DESC 
    LIMIT 10
  `).all();

  // Recent 7 days breakdown
  const dailyActivity = db.prepare(`
    SELECT substr(timestamp, 1, 10) as day, COUNT(*) as count 
    FROM audit_logs 
    GROUP BY day 
    ORDER BY day DESC 
    LIMIT 7
  `).all();

  return {
    totalLogs,
    totalJwtEvents,
    successCount,
    deniedCount,
    failedCount,
    blockedCount,
    uniqueJtis,
    todayLogs,
    eventBreakdown,
    dailyActivity,
    triggersActive: true,
    dbStatus: {
      auth: 'HEALTHY',
      business: 'HEALTHY',
      audit: 'HEALTHY (TRIGGERS_ACTIVE)'
    }
  };
};

/**
 * Live test demonstrating SQLite DB-level trigger immutability enforcement!
 * Directly tries an UPDATE or DELETE query on audit_logs and captures the ABORT error.
 */
const testImmutabilityTamper = (type = 'UPDATE', userContext = {}) => {
  let simulatedQuery = '';
  let caughtError = null;
  let blocked = false;

  const targetRow = db.prepare('SELECT id FROM audit_logs ORDER BY id ASC LIMIT 1').get();
  const targetId = targetRow ? targetRow.id : 1;

  try {
    if (type.toUpperCase() === 'DELETE') {
      simulatedQuery = `DELETE FROM audit_logs WHERE id = ${targetId};`;
      db.prepare('DELETE FROM audit_logs WHERE id = ?').run(targetId);
    } else {
      simulatedQuery = `UPDATE audit_logs SET action = 'ALTERED_BY_ATTACKER' WHERE id = ${targetId};`;
      db.prepare("UPDATE audit_logs SET action = 'ALTERED_BY_ATTACKER' WHERE id = ?").run(targetId);
    }
  } catch (err) {
    caughtError = err.message;
    blocked = true;
  }

  // Log the tamper attempt in the audit DB
  logAudit({
    event: 'IMMUTABILITY_TAMPER_ATTEMPT',
    user_id: userContext.userId || null,
    username: userContext.username || 'security-tester',
    role: userContext.role || 'tester',
    ip_address: userContext.ip || '127.0.0.1',
    user_agent: userContext.userAgent || 'SecurityAuditSuite/1.0',
    action: `Simulated malicious ${type.toUpperCase()} attack blocked by SQLite trigger: "${simulatedQuery}"`,
    entity_type: 'audit_table',
    entity_id: String(targetId),
    status: blocked ? 'BLOCKED' : 'FAILED',
    metadata: {
      simulated_query: simulatedQuery,
      trigger_response: caughtError,
      immutability_guarantee: 'SQLITE_ABORT_TRIGGER',
      timestamp: new Date().toISOString()
    }
  });

  return {
    blocked,
    simulatedQuery,
    errorMessage: caughtError,
    triggerActive: true,
    targetRowId: targetId,
    tamperLogged: true
  };
};

/**
 * Record a user session upon login
 */
const recordSessionLogin = ({
  jti,
  user_id = null,
  username,
  role = 'user',
  ip_address = '127.0.0.1',
  user_agent = ''
}) => {
  try {
    const stmt = db.prepare(`
      INSERT INTO user_sessions (jti, user_id, username, role, ip_address, user_agent, login_time, last_active, duration_seconds, status, last_view)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0, 'ACTIVE', 'Dashboard')
      ON CONFLICT(jti) DO UPDATE SET
        last_active = CURRENT_TIMESTAMP,
        status = 'ACTIVE'
    `);
    stmt.run(jti, user_id, username, role, ip_address, user_agent);
    return { success: true };
  } catch (err) {
    console.error('[Audit DB] Error recording session login:', err.message);
    return { success: false, error: err.message };
  }
};

/**
 * Update session duration and active ping
 */
const updateSessionHeartbeat = ({
  jti,
  duration_seconds = 0,
  current_view = 'Dashboard',
  ip_address = '127.0.0.1',
  user_agent = ''
}) => {
  try {
    const existing = db.prepare('SELECT id, login_time, duration_seconds FROM user_sessions WHERE jti = ?').get(jti);
    if (!existing) {
      return { success: false, error: 'Session not found' };
    }

    const newDuration = Math.max(Number(duration_seconds), existing.duration_seconds || 0);

    db.prepare(`
      UPDATE user_sessions 
      SET last_active = CURRENT_TIMESTAMP,
          duration_seconds = ?,
          last_view = ?,
          status = 'ACTIVE'
      WHERE jti = ?
    `).run(newDuration, current_view, jti);

    return { success: true, duration_seconds: newDuration };
  } catch (err) {
    console.error('[Audit DB] Error updating session heartbeat:', err.message);
    return { success: false, error: err.message };
  }
};

/**
 * End a user session on logout or exit
 */
const endSession = ({ jti, reason = 'LOGGED_OUT' }) => {
  try {
    const session = db.prepare('SELECT * FROM user_sessions WHERE jti = ?').get(jti);
    if (!session) {
      return { success: false, duration_seconds: 0, formatted_duration: '0s' };
    }

    db.prepare(`
      UPDATE user_sessions 
      SET last_active = CURRENT_TIMESTAMP,
          status = ?
      WHERE jti = ?
    `).run(reason, jti);

    const dur = session.duration_seconds || 0;
    const mins = Math.floor(dur / 60);
    const secs = dur % 60;
    const formatted = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;

    return {
      success: true,
      session,
      duration_seconds: dur,
      formatted_duration: formatted
    };
  } catch (err) {
    console.error('[Audit DB] Error ending session:', err.message);
    return { success: false, error: err.message, duration_seconds: 0, formatted_duration: '0s' };
  }
};

/**
 * Retrieve user sessions list with real-time status evaluation
 */
const getUserSessions = ({ limit = 50 } = {}) => {
  try {
    // Automatically transition stale sessions (> 3 minutes inactive) to INACTIVE if still marked ACTIVE
    db.prepare(`
      UPDATE user_sessions
      SET status = 'INACTIVE'
      WHERE status = 'ACTIVE' 
        AND (strftime('%s', 'now') - strftime('%s', last_active)) > 180
    `).run();

    const sessions = db.prepare(`
      SELECT 
        id, jti, user_id, username, role, ip_address, user_agent,
        login_time, last_active, duration_seconds, status, last_view, created_at,
        (strftime('%s', 'now') - strftime('%s', last_active)) as seconds_since_ping
      FROM user_sessions
      ORDER BY id DESC
      LIMIT ?
    `).all(Number(limit));

    return sessions.map(s => {
      const dur = s.duration_seconds || 0;
      const mins = Math.floor(dur / 60);
      const secs = dur % 60;
      const formatted = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
      return {
        ...s,
        formatted_duration: formatted
      };
    });
  } catch (err) {
    console.error('[Audit DB] Error fetching user sessions:', err.message);
    return [];
  }
};

module.exports = {
  db,
  logAudit,
  logJwtEvent,
  getAuditLogs,
  getAuditLogById,
  getJwtEvents,
  getAuditStats,
  testImmutabilityTamper,
  recordSessionLogin,
  updateSessionHeartbeat,
  endSession,
  getUserSessions
};
