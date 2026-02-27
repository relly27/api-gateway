const pool = require('../db/db');

/**
 * Middleware to record all gateway transactions in the audit_logs table.
 */
const auditMiddleware = (req, res, next) => {
  const method = req.headers['x-original-method'] || req.method;
  const path = req.headers['x-original-uri'] || req.path;
  const { ip, headers } = req;
  const userAgent = headers['user-agent'];

  // Listen for the response to finish to capture the status code
  res.on('finish', async () => {
    const userId = req.user ? req.user.id : null;
    const statusCode = res.statusCode;

    // Determine action type
    let action = 'Gateway Request';
    if (path === '/auth/login') action = 'Login Attempt';
    if (path === '/auth/register') action = 'Registration Attempt';
    if (path === '/auth/logout') action = 'Logout Action';

    try {
      // Record the transaction in the database
      await pool.query(
        `INSERT INTO audit_logs
         (user_id, action, method, path, status_code, ip_address, user_agent, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          userId,
          action,
          method,
          path,
          statusCode,
          ip,
          userAgent,
          JSON.stringify({
            query: req.query,
            success: statusCode >= 200 && statusCode < 300,
            // Log email for login attempts to track failures by user
            email: (path === '/auth/login' || path === '/auth/register') ? req.body.email : undefined,
            hasBody: Object.keys(req.body || {}).length > 0
          })
        ]
      );
    } catch (error) {
      // We don't want to crash the request if auditing fails, but we should log it
      console.error('Audit logging failed:', error);
    }
  });

  next();
};

module.exports = auditMiddleware;
