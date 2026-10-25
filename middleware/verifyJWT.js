const { verifyAccessToken } = require('../utils/jwt');
const auditDb = require('../db/audit');

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization || req.headers.Authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Missing or malformed Authorization header. Expected Bearer <token>',
      code: 'UNAUTHORIZED'
    });
  }

  const token = authHeader.split(' ')[1];
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  try {
    const decoded = verifyAccessToken(token);
    req.user = decoded;

    // Log VERIFIED event to jwt_events (Traceability requirement)
    auditDb.logJwtEvent({
      jti: decoded.jti,
      event_type: 'VERIFIED',
      user_id: decoded.sub,
      username: decoded.username,
      endpoint: `${req.method} ${req.baseUrl || ''}${req.path}`,
      ip_address: ip,
      user_agent: userAgent
    });

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      // Decode unverified to capture JTI if possible for forensic audit
      try {
        const jwt = require('jsonwebtoken');
        const expiredDecoded = jwt.decode(token);
        if (expiredDecoded && expiredDecoded.jti) {
          auditDb.logJwtEvent({
            jti: expiredDecoded.jti,
            event_type: 'EXPIRED',
            user_id: expiredDecoded.sub,
            username: expiredDecoded.username,
            endpoint: `${req.method} ${req.baseUrl || ''}${req.path}`,
            ip_address: ip,
            user_agent: userAgent,
            details: { expired_at: err.expiredAt }
          });
        }
      } catch (e) {
        // ignore decode error on expired
      }

      return res.status(401).json({
        error: 'Access token has expired',
        code: 'TOKEN_EXPIRED'
      });
    }

    return res.status(401).json({
      error: 'Invalid or tampered access token',
      code: 'INVALID_TOKEN'
    });
  }
};

module.exports = verifyJWT;
