const db = require('../db');

const auditRequest = async (req, res, next) => {
  // We log after the request is finished or at least after it passes auth
  const start = Date.now();

  res.on('finish', async () => {
    if (req.user) {
      try {
        const duration = Date.now() - start;
        await db.query(
          'INSERT INTO audit_logs (user_id, action, details, ip_address, device_info) VALUES ($1, $2, $3, $4, $5)',
          [
            req.user.userId,
            'API_REQUEST',
            JSON.stringify({
              method: req.method,
              url: req.originalUrl,
              statusCode: res.statusCode,
              duration: `${duration}ms`
            }),
            req.ip,
            req.headers['user-agent']
          ]
        );
      } catch (err) {
        console.error('Failed to log audit:', err);
      }
    }
  });

  next();
};

module.exports = auditRequest;
