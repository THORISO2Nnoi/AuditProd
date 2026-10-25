const express = require('express');
const router = express.Router();
const auditDb = require('../db/audit');
const verifyJWT = require('../middleware/verifyJWT');
const requireRole = require('../middleware/requireRole');

// All audit endpoints require valid JWT authentication
router.use(verifyJWT);

/**
 * POST /api/audit/view
 * Record an uneditable view footprint (e.g. user viewed catalog, tasks, reports, etc.)
 * Available to ALL authenticated users so all footprints are captured
 */
router.post('/view', (req, res) => {
  const { viewName, entityType, entityId, durationInView } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  const sanitizedView = (viewName || 'Dashboard').trim();
  const eventName = `VIEW_${sanitizedView.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;

  const result = auditDb.logAudit({
    event: eventName,
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `User '${req.user.username}' viewed ${sanitizedView}${entityId ? ` (${entityId})` : ''}`,
    entity_type: entityType || 'view_footprint',
    entity_id: entityId ? String(entityId) : sanitizedView,
    jti: req.user.jti,
    status: 'SUCCESS',
    metadata: {
      section: sanitizedView,
      duration_in_view_seconds: durationInView || 0,
      footprint_type: 'VIEW',
      immutable: true
    }
  });

  return res.json({ success: true, logId: result.id });
});

// Forensic inspection routes are restricted to Admin and Auditor only
router.use(requireRole('admin', 'auditor'));

/**
 * GET /api/audit/sessions
 * Returns user sessions showing how long each user has stayed in the system
 */
router.get('/sessions', (req, res) => {
  const limit = req.query.limit ? parseInt(req.query.limit) : 50;
  const sessions = auditDb.getUserSessions({ limit });
  return res.json({ sessions });
});

/**
 * GET /api/audit/logs
 * Filtered, paginated audit logs
 */
router.get('/logs', (req, res) => {
  const { page, limit, username, event, status, entity_type, search, dateFrom, dateTo } = req.query;

  const result = auditDb.getAuditLogs({
    page: page ? parseInt(page) : 1,
    limit: limit ? parseInt(limit) : 15,
    username,
    event,
    status,
    entity_type,
    search,
    dateFrom,
    dateTo
  });

  return res.json(result);
});

/**
 * GET /api/audit/logs/:id
 * Detailed forensic snapshot for Before/After modal
 */
router.get('/logs/:id', (req, res) => {
  const log = auditDb.getAuditLogById(req.params.id);
  if (!log) {
    return res.status(404).json({ error: 'Audit log record not found' });
  }

  // Parse JSON snapshots and diff for frontend rendering
  let before = null;
  let after = null;
  let diff = null;
  let metadata = null;

  try { if (log.before_snapshot) before = JSON.parse(log.before_snapshot); } catch (e) { before = log.before_snapshot; }
  try { if (log.after_snapshot) after = JSON.parse(log.after_snapshot); } catch (e) { after = log.after_snapshot; }
  try { if (log.diff) diff = JSON.parse(log.diff); } catch (e) { diff = log.diff; }
  try { if (log.metadata) metadata = JSON.parse(log.metadata); } catch (e) { metadata = log.metadata; }

  return res.json({
    log: {
      ...log,
      before_snapshot_parsed: before,
      after_snapshot_parsed: after,
      diff_parsed: diff,
      metadata_parsed: metadata
    }
  });
});

/**
 * GET /api/audit/export/csv
 * Generates an immutable forensic CSV export.
 * Note: The export action itself is strictly audited!
 */
router.get('/export/csv', (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  // Fetch up to 1000 logs matching current filters
  const result = auditDb.getAuditLogs({
    page: 1,
    limit: 1000,
    username: req.query.username,
    event: req.query.event,
    status: req.query.status,
    entity_type: req.query.entity_type,
    search: req.query.search,
    dateFrom: req.query.dateFrom,
    dateTo: req.query.dateTo
  });

  const logs = result.logs;

  // Audit the export action itself!
  auditDb.logAudit({
    event: 'EXPORT_REPORT',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `User '${req.user.username}' exported ${logs.length} audit rows to CSV format`,
    entity_type: 'report',
    entity_id: 'csv-export',
    jti: req.user.jti,
    status: 'SUCCESS',
    metadata: {
      format: 'CSV',
      rows_count: logs.length,
      filters_applied: req.query
    }
  });

  // Build CSV content
  const headers = ['ID', 'Timestamp', 'Event', 'Username', 'Role', 'IP_Address', 'Status', 'Action', 'Entity_Type', 'Entity_ID'];
  const csvLines = [headers.join(',')];

  for (const log of logs) {
    const row = [
      log.id,
      `"${log.timestamp}"`,
      `"${log.event}"`,
      `"${log.username || ''}"`,
      `"${log.role || ''}"`,
      `"${log.ip_address || ''}"`,
      `"${log.status || ''}"`,
      `"${(log.action || '').replace(/"/g, '""')}"`,
      `"${log.entity_type || ''}"`,
      `"${log.entity_id || ''}"`
    ];
    csvLines.push(row.join(','));
  }

  const csvData = csvLines.join('\r\n');
  const filename = `auditpro-compliance-export-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  return res.send(csvData);
});

/**
 * GET /api/audit/export/json
 * Export filtered logs as JSON
 */
router.get('/export/json', (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  const result = auditDb.getAuditLogs({
    page: 1,
    limit: 1000,
    username: req.query.username,
    event: req.query.event,
    status: req.query.status,
    entity_type: req.query.entity_type,
    search: req.query.search,
    dateFrom: req.query.dateFrom,
    dateTo: req.query.dateTo
  });

  // Audit the export action
  auditDb.logAudit({
    event: 'EXPORT_REPORT',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `User '${req.user.username}' exported ${result.logs.length} audit rows to JSON format`,
    entity_type: 'report',
    entity_id: 'json-export',
    jti: req.user.jti,
    status: 'SUCCESS',
    metadata: {
      format: 'JSON',
      rows_count: result.logs.length,
      filters_applied: req.query
    }
  });

  const filename = `auditpro-compliance-export-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  return res.json({
    exported_at: new Date().toISOString(),
    exported_by: req.user.username,
    total_records: result.logs.length,
    records: result.logs
  });
});

/**
 * GET /api/audit/jwt-events
 * Inspection of JWT lifecycle trace (ISSUED, VERIFIED, EXPIRED, REFRESHED, REVOKED)
 */
router.get('/jwt-events', (req, res) => {
  const { limit, jti, username } = req.query;
  const events = auditDb.getJwtEvents({
    limit: limit ? parseInt(limit) : 50,
    jti,
    username
  });

  return res.json({ events });
});

/**
 * POST /api/audit/test-immutability
 * Live tamper test: Attempts direct UPDATE or DELETE query on SQLite audit_logs
 * and verifies that SQLite trigger aborts and rejects the query!
 */
router.post('/test-immutability', (req, res) => {
  const { type = 'UPDATE' } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  const testResult = auditDb.testImmutabilityTamper(type, {
    userId: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip,
    userAgent
  });

  return res.json({
    message: 'Immutability defense test executed',
    ...testResult
  });
});

module.exports = router;
