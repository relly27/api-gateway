const authService = require('../services/authService');

/**
 * Middleware to authenticate requests via JWT.
 * It also prevents header spoofing by stripping sensitive headers.
 */
const authMiddleware = async (req, res, next) => {
  // 1. Prevent header spoofing: Strip incoming X-User-* headers from the client
  const sensitiveHeaders = ['x-user-id', 'x-user-email', 'x-user-role', 'x-user-department-id'];
  sensitiveHeaders.forEach(header => delete req.headers[header]);

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // If no token is provided, we don't set req.user.
    // Downstream middlewares (like authorizeMiddleware) will decide if this is allowed.
    return next();
  }

  const token = authHeader.split(' ')[1];
  const decoded = await authService.verifyToken(token);

  if (!decoded) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Invalid or expired session'
    });
  }

  // Attach user info to request object
  req.user = {
    id: decoded.id,
    email: decoded.email,
    role: decoded.role,
    department_id: decoded.department_id,
    jti: decoded.jti
  };

  // Inject validated user headers for downstream microservices
  req.headers['x-user-id'] = req.user.id.toString();
  req.headers['x-user-email'] = req.user.email;
  req.headers['x-user-role'] = req.user.role;
  req.headers['x-user-department-id'] = req.user.department_id ? req.user.department_id.toString() : '';

  next();
};

module.exports = authMiddleware;
