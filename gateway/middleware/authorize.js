const db = require('../db');

const authorize = (requiredPermission) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    try {
      // Check if user has the required permission through their roles
      const permissionResult = await db.query(
        `SELECT p.name
         FROM permissions p
         JOIN role_permissions rp ON p.id = rp.permission_id
         JOIN user_roles ur ON rp.role_id = ur.role_id
         WHERE ur.user_id = $1 AND p.name = $2`,
        [req.user.userId, requiredPermission]
      );

      // Also check for 'admin' role which might have all permissions bypass
      const adminResult = await db.query(
        `SELECT r.name
         FROM roles r
         JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_id = $1 AND r.name = 'admin'`,
        [req.user.userId]
      );

      if (permissionResult.rows.length > 0 || adminResult.rows.length > 0) {
        return next();
      }

      return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };
};

module.exports = authorize;
