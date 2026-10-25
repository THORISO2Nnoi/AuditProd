const express = require('express');
const router = express.Router();
const authDb = require('../db/auth');
const auditDb = require('../db/audit');
const { calculateDiff } = require('../utils/diff');
const verifyJWT = require('../middleware/verifyJWT');
const requireRole = require('../middleware/requireRole');

// All routes in this file require Admin role
router.use(verifyJWT);
router.use(requireRole('admin'));

/**
 * GET /api/users
 * List all registered users (Admin only)
 */
router.get('/', (req, res) => {
  const users = authDb.getAllUsers();
  return res.json({ users });
});

/**
 * POST /api/users
 * Provision a new user (Admin only)
 */
router.post('/', (req, res) => {
  const { username, password, role, full_name } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  if (!username || !password || !role || !full_name) {
    return res.status(400).json({ error: 'All fields (username, password, role, full_name) are required' });
  }

  if (!['admin', 'auditor', 'user'].includes(role)) {
    return res.status(400).json({ error: 'Role must be admin, auditor, or user' });
  }

  const existing = authDb.getUserByUsername(username);
  if (existing) {
    return res.status(409).json({ error: `Username '${username}' is already in use` });
  }

  const newUser = authDb.createUser({ username, password, role, full_name });

  // Forensic Audit Log
  auditDb.logAudit({
    event: 'CREATE_USER',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `Admin provisioned new identity '${newUser.username}' with role '${newUser.role}'`,
    entity_type: 'user',
    entity_id: newUser.id,
    before_snapshot: null,
    after_snapshot: { id: newUser.id, username: newUser.username, role: newUser.role, full_name: newUser.full_name },
    diff: { created: { role: newUser.role, username: newUser.username } },
    jti: req.user.jti,
    status: 'SUCCESS'
  });

  return res.status(201).json({ user: newUser });
});

/**
 * PUT /api/users/:id
 * Update an existing user role or profile (Admin only)
 */
router.put('/:id', (req, res) => {
  const { id } = req.params;
  const { role, full_name, password } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  const beforeUser = authDb.getUserById(id);
  if (!beforeUser) {
    return res.status(404).json({ error: 'User not found' });
  }

  const updatedUser = authDb.updateUser(id, { role, full_name, password });
  const { changedFields, diff } = calculateDiff(beforeUser, updatedUser);

  // Forensic Audit Log with Yellow-diff snapshots
  auditDb.logAudit({
    event: 'UPDATE_USER',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `Admin updated account '${updatedUser.username}': [${changedFields.join(', ')}]`,
    entity_type: 'user',
    entity_id: updatedUser.id,
    before_snapshot: beforeUser,
    after_snapshot: updatedUser,
    diff: diff,
    jti: req.user.jti,
    status: 'SUCCESS',
    metadata: { password_changed: !!password }
  });

  return res.json({ user: updatedUser, diff });
});

/**
 * DELETE /api/users/:id
 * Remove user identity (Admin only)
 */
router.delete('/:id', (req, res) => {
  const { id } = req.params;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  const beforeUser = authDb.getUserById(id);
  if (!beforeUser) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Prevent self-deletion
  if (beforeUser.id === req.user.sub) {
    return res.status(400).json({ error: 'Cannot delete your own active administrator account' });
  }

  const deletedUser = authDb.deleteUser(id);

  // Forensic Audit Log
  auditDb.logAudit({
    event: 'DELETE_USER',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `Admin deleted user '${deletedUser.username}' (role: ${deletedUser.role})`,
    entity_type: 'user',
    entity_id: deletedUser.id,
    before_snapshot: deletedUser,
    after_snapshot: null,
    diff: { deleted: deletedUser.username },
    jti: req.user.jti,
    status: 'SUCCESS'
  });

  return res.json({ message: `User '${deletedUser.username}' successfully deleted`, user: deletedUser });
});

module.exports = router;
