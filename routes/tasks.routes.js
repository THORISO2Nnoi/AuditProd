const express = require('express');
const router = express.Router();
const businessDb = require('../db/business');
const auditDb = require('../db/audit');
const { calculateDiff } = require('../utils/diff');
const verifyJWT = require('../middleware/verifyJWT');
const requireRole = require('../middleware/requireRole');

router.use(verifyJWT);

/**
 * GET /api/tasks
 * Admin/Auditor see all tasks; Standard User sees only their assigned or created tasks
 */
router.get('/', (req, res) => {
  let tasks;
  if (req.user.role === 'admin' || req.user.role === 'auditor') {
    tasks = businessDb.getTasks();
  } else {
    // Isolated User Workspace
    tasks = businessDb.getTasks({ username: req.user.username });
  }

  return res.json({ tasks });
});

/**
 * POST /api/tasks
 * Create a new task (Admin or User. Auditor is strictly read-only)
 */
router.post('/', (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  // Compliance rule: Auditor is strictly read-only on operational data
  if (req.user.role === 'auditor') {
    auditDb.logAudit({
      event: 'ACCESS_DENIED',
      user_id: req.user.sub,
      username: req.user.username,
      role: req.user.role,
      ip_address: ip,
      user_agent: userAgent,
      action: `Auditor '${req.user.username}' attempted to create a task (read-only compliance restriction)`,
      entity_type: 'task',
      entity_id: 'new',
      jti: req.user.jti,
      status: 'DENIED'
    });

    return res.status(403).json({
      error: 'Auditor accounts are restricted to read-only compliance inspection',
      code: 'AUDITOR_READ_ONLY'
    });
  }

  const { title, description, priority, status, assigned_to, due_date } = req.body;
  if (!title) {
    return res.status(400).json({ error: 'Task title is required' });
  }

  // Regular users can only assign to themselves or leave default
  let assignee = assigned_to || req.user.username;
  if (req.user.role === 'user') {
    assignee = req.user.username; // enforce self-assignment for standard users
  }

  const newTask = businessDb.createTask({
    title,
    description,
    priority,
    status: status || 'pending',
    assigned_to: assignee,
    created_by: req.user.username,
    due_date
  });

  // Forensic Audit Log
  auditDb.logAudit({
    event: 'CREATE_TASK',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `User '${req.user.username}' created task '${newTask.title}' assigned to '${newTask.assigned_to}'`,
    entity_type: 'task',
    entity_id: newTask.id,
    before_snapshot: null,
    after_snapshot: newTask,
    diff: { created: newTask },
    jti: req.user.jti,
    status: 'SUCCESS'
  });

  return res.status(201).json({ task: newTask });
});

/**
 * PUT /api/tasks/:id
 * Update task status or details
 */
router.put('/:id', (req, res) => {
  const { id } = req.params;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  // Compliance check: Auditor is read-only
  if (req.user.role === 'auditor') {
    auditDb.logAudit({
      event: 'ACCESS_DENIED',
      user_id: req.user.sub,
      username: req.user.username,
      role: req.user.role,
      ip_address: ip,
      user_agent: userAgent,
      action: `Auditor '${req.user.username}' attempted to update task ${id}`,
      entity_type: 'task',
      entity_id: id,
      jti: req.user.jti,
      status: 'DENIED'
    });
    return res.status(403).json({ error: 'Auditor accounts are read-only' });
  }

  const beforeTask = businessDb.getTaskById(id);
  if (!beforeTask) {
    return res.status(404).json({ error: 'Task not found' });
  }

  // Least-privilege isolation: Regular user can only modify their own task
  if (req.user.role === 'user' && beforeTask.assigned_to !== req.user.username && beforeTask.created_by !== req.user.username) {
    auditDb.logAudit({
      event: 'ACCESS_DENIED',
      user_id: req.user.sub,
      username: req.user.username,
      role: req.user.role,
      ip_address: ip,
      user_agent: userAgent,
      action: `User '${req.user.username}' attempted unauthorized modification of task ${id} assigned to '${beforeTask.assigned_to}'`,
      entity_type: 'task',
      entity_id: id,
      jti: req.user.jti,
      status: 'DENIED'
    });

    return res.status(403).json({ error: 'You are only authorized to modify your own tasks' });
  }

  const updatedTask = businessDb.updateTask(id, req.body);
  const { changedFields, diff } = calculateDiff(beforeTask, updatedTask);

  // Forensic Audit Log with Yellow Diff
  auditDb.logAudit({
    event: 'UPDATE_TASK',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `Updated task '${updatedTask.title}' (${changedFields.join(', ')})`,
    entity_type: 'task',
    entity_id: updatedTask.id,
    before_snapshot: beforeTask,
    after_snapshot: updatedTask,
    diff: diff,
    jti: req.user.jti,
    status: 'SUCCESS'
  });

  return res.json({ task: updatedTask, diff });
});

/**
 * DELETE /api/tasks/:id
 */
router.delete('/:id', (req, res) => {
  const { id } = req.params;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  if (req.user.role === 'auditor') {
    return res.status(403).json({ error: 'Auditor accounts are read-only' });
  }

  const beforeTask = businessDb.getTaskById(id);
  if (!beforeTask) {
    return res.status(404).json({ error: 'Task not found' });
  }

  if (req.user.role === 'user' && beforeTask.created_by !== req.user.username) {
    auditDb.logAudit({
      event: 'ACCESS_DENIED',
      user_id: req.user.sub,
      username: req.user.username,
      role: req.user.role,
      ip_address: ip,
      user_agent: userAgent,
      action: `User '${req.user.username}' attempted unauthorized deletion of task ${id}`,
      entity_type: 'task',
      entity_id: id,
      jti: req.user.jti,
      status: 'DENIED'
    });
    return res.status(403).json({ error: 'You can only delete tasks you created' });
  }

  const deleted = businessDb.deleteTask(id);

  // Forensic Audit Log
  auditDb.logAudit({
    event: 'DELETE_TASK',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `Deleted task '${deleted.title}'`,
    entity_type: 'task',
    entity_id: deleted.id,
    before_snapshot: deleted,
    after_snapshot: null,
    diff: { deleted: deleted.title },
    jti: req.user.jti,
    status: 'SUCCESS'
  });

  return res.json({ message: 'Task deleted', task: deleted });
});

module.exports = router;
