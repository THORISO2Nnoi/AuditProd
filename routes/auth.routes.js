const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const authDb = require('../db/auth');
const auditDb = require('../db/audit');
const { generateTokenPair, verifyRefreshToken, hashToken } = require('../utils/jwt');
const verifyJWT = require('../middleware/verifyJWT');

/**
 * POST /api/auth/login
 * Authenticates user, generates tokens with JTI, logs LOGIN or LOGIN_FAILED
 */
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = authDb.getUserByUsername(username);

  // Failure scenario
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    auditDb.logAudit({
      event: 'LOGIN_FAILED',
      user_id: user ? user.id : null,
      username: username,
      role: user ? user.role : 'unauthenticated',
      ip_address: ip,
      user_agent: userAgent,
      action: `Failed authentication attempt for username '${username}'`,
      entity_type: 'identity',
      entity_id: username,
      status: 'FAILED',
      metadata: { reason: user ? 'Invalid password credentials' : 'User not found in auth.db' }
    });

    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // Success scenario
  const tokens = generateTokenPair(user, { ip, userAgent, endpoint: '/api/auth/login' });

  // Record active session footprint in audit DB
  auditDb.recordSessionLogin({
    jti: tokens.jti,
    user_id: user.id,
    username: user.username,
    role: user.role,
    ip_address: ip,
    user_agent: userAgent
  });

  auditDb.logAudit({
    event: 'LOGIN',
    user_id: user.id,
    username: user.username,
    role: user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `User '${user.username}' successfully authenticated with role '${user.role}'`,
    entity_type: 'identity',
    entity_id: user.id,
    jti: tokens.jti,
    status: 'SUCCESS',
    metadata: {
      auth_method: 'password_bcrypt',
      role: user.role,
      token_jti: tokens.jti
    }
  });

  return res.json({
    message: 'Authentication successful',
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      full_name: user.full_name
    },
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    jti: tokens.jti,
    expiresIn: tokens.expiresIn
  });
});

/**
 * POST /api/auth/refresh
 * Rotates refresh token, invalidating the old one and issuing new access/refresh pair
 */
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  try {
    const decoded = verifyRefreshToken(refreshToken);
    const tokenHash = hashToken(refreshToken);
    const storedToken = authDb.findRefreshToken(tokenHash);

    if (!storedToken) {
      return res.status(401).json({ error: 'Unrecognized refresh token' });
    }

    if (storedToken.revoked) {
      // Possible token reuse attack! Revoke all tokens for this user
      authDb.revokeAllUserTokens(storedToken.user_id);
      
      auditDb.logAudit({
        event: 'SECURITY_ALERT',
        user_id: storedToken.user_id,
        username: decoded.username,
        role: 'unknown',
        ip_address: ip,
        user_agent: userAgent,
        action: `Detected reuse of revoked refresh token! Revoked all active sessions for user.`,
        entity_type: 'session',
        entity_id: storedToken.user_id,
        status: 'FAILED',
        metadata: { reused_jti: storedToken.jti }
      });

      return res.status(403).json({ error: 'Compromised token detected. All sessions revoked.' });
    }

    // Check expiration
    if (new Date(storedToken.expires_at) < new Date()) {
      return res.status(401).json({ error: 'Refresh token has expired' });
    }

    const user = authDb.getUserById(storedToken.user_id);
    if (!user) {
      return res.status(401).json({ error: 'User associated with token no longer exists' });
    }

    // Generate new pair
    const tokens = generateTokenPair(user, { ip, userAgent, endpoint: '/api/auth/refresh' });

    // Revoke old token and link to replacement
    authDb.revokeRefreshToken(tokenHash, hashToken(tokens.refreshToken));

    // Audit log
    auditDb.logJwtEvent({
      jti: storedToken.jti,
      event_type: 'REFRESHED',
      user_id: user.id,
      username: user.username,
      endpoint: '/api/auth/refresh',
      ip_address: ip,
      user_agent: userAgent,
      details: { new_jti: tokens.jti }
    });

    auditDb.logAudit({
      event: 'REFRESH_TOKEN',
      user_id: user.id,
      username: user.username,
      role: user.role,
      ip_address: ip,
      user_agent: userAgent,
      action: `Rotated JWT session for '${user.username}' (New JTI: ${tokens.jti})`,
      entity_type: 'identity',
      entity_id: user.id,
      jti: tokens.jti,
      status: 'SUCCESS'
    });

    return res.json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      jti: tokens.jti,
      expiresIn: tokens.expiresIn
    });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

/**
 * POST /api/auth/logout
 * Explicitly revokes refresh token and logs audit trail
 */
router.post('/logout', verifyJWT, (req, res) => {
  const { refreshToken, durationSeconds } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  if (refreshToken) {
    const tokenHash = hashToken(refreshToken);
    authDb.revokeRefreshToken(tokenHash);
  }

  // End session and calculate total time stayed in the system
  if (durationSeconds) {
    auditDb.updateSessionHeartbeat({
      jti: req.user.jti,
      duration_seconds: durationSeconds
    });
  }
  const endedSession = auditDb.endSession({ jti: req.user.jti, reason: 'LOGGED_OUT' });
  const formattedStay = endedSession.formatted_duration || '0s';

  // Log REVOKED event for current access token
  auditDb.logJwtEvent({
    jti: req.user.jti,
    event_type: 'REVOKED',
    user_id: req.user.sub,
    username: req.user.username,
    endpoint: '/api/auth/logout',
    ip_address: ip,
    user_agent: userAgent
  });

  auditDb.logAudit({
    event: 'LOGOUT',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `User '${req.user.username}' signed out (Total time stayed in system: ${formattedStay})`,
    entity_type: 'identity',
    entity_id: req.user.sub,
    jti: req.user.jti,
    status: 'SUCCESS',
    metadata: {
      total_duration_seconds: endedSession.duration_seconds,
      formatted_duration: formattedStay
    }
  });

  return res.json({ 
    message: 'Logged out successfully',
    timeStayed: formattedStay,
    durationSeconds: endedSession.duration_seconds
  });
});

/**
 * POST /api/auth/heartbeat
 * Receives live active heartbeat from browser with session duration and current active view
 */
router.post('/heartbeat', verifyJWT, (req, res) => {
  const { durationSeconds, currentView } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  const updateResult = auditDb.updateSessionHeartbeat({
    jti: req.user.jti,
    duration_seconds: Number(durationSeconds) || 0,
    current_view: currentView || 'Dashboard',
    ip_address: ip,
    user_agent: userAgent
  });

  return res.json({ ok: true, session: updateResult });
});

/**
 * GET /api/auth/me
 * Returns currently authenticated user details
 */
router.get('/me', verifyJWT, (req, res) => {
  const user = authDb.getUserById(req.user.sub);
  if (!user) {
    return res.status(404).json({ error: 'User record not found' });
  }

  return res.json({
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      full_name: user.full_name,
      created_at: user.created_at
    },
    jti: req.user.jti
  });
});

/**
 * POST /api/auth/quick-switch
 * Dedicated demo endpoint allowing 1-click role testing (admin, auditor, alice, bob)
 */
router.post('/quick-switch', (req, res) => {
  const { targetUsername } = req.body;
  const allowed = ['admin', 'auditor', 'alice', 'bob'];

  if (!allowed.includes(targetUsername)) {
    return res.status(400).json({ error: 'Invalid demo user' });
  }

  const user = authDb.getUserByUsername(targetUsername);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'AuditPro-Demo-Switcher';

  const tokens = generateTokenPair(user, { ip, userAgent, endpoint: '/api/auth/quick-switch' });

  auditDb.logAudit({
    event: 'LOGIN',
    user_id: user.id,
    username: user.username,
    role: user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `Demo Quick-Switch to role '${user.role}' as '${user.username}'`,
    entity_type: 'identity',
    entity_id: user.id,
    jti: tokens.jti,
    status: 'SUCCESS',
    metadata: { demo_mode: true, role: user.role }
  });

  return res.json({
    message: `Switched context to ${user.username}`,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      full_name: user.full_name
    },
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    jti: tokens.jti,
    expiresIn: tokens.expiresIn
  });
});

module.exports = router;
