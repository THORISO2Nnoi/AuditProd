const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const authDb = require('../db/auth');
const auditDb = require('../db/audit');

const JWT_SECRET = process.env.JWT_SECRET || 'auditpro_super_secure_jwt_access_secret_key_compliance_ready_2026';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'auditpro_super_secure_refresh_token_rotation_secret_2026';
const ACCESS_EXPIRES_IN = process.env.JWT_EXPIRY || '15m';
const REFRESH_EXPIRES_IN = process.env.REFRESH_EXPIRY || '7d';

/**
 * Hash a token string using SHA-256 for database storage
 */
const hashToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

/**
 * Generate Access and Refresh token pair with unique JTI tracking
 */
const generateTokenPair = (user, { ip = '127.0.0.1', userAgent = '', endpoint = '/api/auth/login' } = {}) => {
  const accessJti = crypto.randomUUID();
  const refreshJti = crypto.randomUUID();

  // 15-minute access token payload
  const accessPayload = {
    sub: user.id,
    username: user.username,
    role: user.role,
    full_name: user.full_name,
    jti: accessJti
  };

  const accessToken = jwt.sign(accessPayload, JWT_SECRET, {
    expiresIn: ACCESS_EXPIRES_IN
  });

  // 7-day refresh token payload
  const refreshPayload = {
    sub: user.id,
    username: user.username,
    jti: refreshJti,
    type: 'refresh'
  };

  const refreshToken = jwt.sign(refreshPayload, REFRESH_SECRET, {
    expiresIn: REFRESH_EXPIRES_IN
  });

  // Calculate refresh expiration date (7 days)
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const tokenHash = hashToken(refreshToken);

  // Store in auth.db
  authDb.storeRefreshToken({
    id: crypto.randomUUID(),
    userId: user.id,
    tokenHash,
    jti: refreshJti,
    expiresAt
  });

  // Log ISSUED event in audit.db (Audit isolation)
  auditDb.logJwtEvent({
    jti: accessJti,
    event_type: 'ISSUED',
    user_id: user.id,
    username: user.username,
    endpoint,
    ip_address: ip,
    user_agent: userAgent,
    details: {
      type: 'access_token',
      expires_in: ACCESS_EXPIRES_IN,
      refresh_jti: refreshJti
    }
  });

  return {
    accessToken,
    refreshToken,
    jti: accessJti,
    expiresIn: 15 * 60 // 15 mins in seconds
  };
};

/**
 * Verify access token
 */
const verifyAccessToken = (token) => {
  return jwt.verify(token, JWT_SECRET);
};

/**
 * Verify refresh token
 */
const verifyRefreshToken = (token) => {
  return jwt.verify(token, REFRESH_SECRET);
};

module.exports = {
  generateTokenPair,
  verifyAccessToken,
  verifyRefreshToken,
  hashToken
};
