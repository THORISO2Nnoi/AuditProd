const auditDb = require('../db/audit');

/**
 * Role-based access control guard middleware
 * Automatically logs ACCESS_DENIED events to the immutable audit database
 */
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required before role verification',
        code: 'UNAUTHENTICATED'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
      const userAgent = req.headers['user-agent'] || 'Unknown-Client';
      const targetEndpoint = `${req.method} ${req.baseUrl || ''}${req.path}`;

      // Forensic ACCESS_DENIED log entry in audit.db
      auditDb.logAudit({
        event: 'ACCESS_DENIED',
        user_id: req.user.sub,
        username: req.user.username,
        role: req.user.role,
        ip_address: ip,
        user_agent: userAgent,
        action: `Blocked access to ${targetEndpoint}. Required roles: [${allowedRoles.join(', ')}], User role: [${req.user.role}]`,
        entity_type: 'endpoint',
        entity_id: targetEndpoint,
        jti: req.user.jti,
        status: 'DENIED',
        metadata: {
          attempted_endpoint: targetEndpoint,
          required_roles: allowedRoles,
          user_role: req.user.role,
          http_method: req.method
        }
      });

      return res.status(403).json({
        error: `Access Denied: Your role '${req.user.role}' lacks authorization for this resource. Required: [${allowedRoles.join(', ')}]`,
        code: 'FORBIDDEN',
        requiredRoles: allowedRoles,
        currentRole: req.user.role
      });
    }

    next();
  };
};

module.exports = requireRole;
