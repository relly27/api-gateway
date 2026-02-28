const pool = require('../db/db');

/**
 * Middleware to handle authorization (RBAC, Ownership, Department restrictions).
 */
const authorizeMiddleware = async (req, res, next) => {
  // Support for Nginx auth_request subrequests
  const method = req.headers['x-original-method'] || req.method;
  const path = req.headers['x-original-uri'] || req.path;

  try {
    // 1. Find the permission configuration for this route and method
    // We look for the most specific match (longest route_path that matches the beginning of current path)
    const result = await pool.query(
      `SELECT * FROM permissions
       WHERE method = $1 AND $2 LIKE route_path || '%'
       ORDER BY length(route_path) DESC LIMIT 1`,
      [method, path]
    );

    const config = result.rows[0];

    if (!config) {
      return res.status(404).json({
        success: false,
        message: 'Route not configured in gateway'
      });
    }

    // Attach config to request for use in the gateway/proxy logic
    req.gatewayConfig = config;

    // 2. Check if route is public
    if (config.is_public) {
      return next();
    }

    // 3. Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    // 4. Check RBAC (Role-Based Access Control)
    // Admins have access to everything by default in many systems,
    // but we'll check the role_permissions table for flexibility.
    const rbacResult = await pool.query(
      `SELECT 1 FROM role_permissions rp
       JOIN roles r ON rp.role_id = r.id
       WHERE r.name = $1 AND rp.permission_id = $2`,
      [req.user.role, config.id]
    );

    if (rbacResult.rows.length === 0 && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden: Insufficient permissions'
      });
    }

    // 5. Owner Validation
    // If is_owner_resource is true, we check if the user is accessing their own data.
    if (config.is_owner_resource && req.user.role !== 'admin') {
      const pathParts = path.split('/').filter(p => p);
      const lastSegment = pathParts[pathParts.length - 1];

      // Special case for profile
      if (path.includes('/profile')) {
        // Accessing own profile is always allowed if authenticated
      } else if (lastSegment !== req.user.id.toString()) {
        // Check if the last segment of the path matches the user ID
        return res.status(403).json({
          success: false,
          message: 'Forbidden: You do not own this resource'
        });
      }
    }

    // 6. Department-based restrictions
    if (config.department_id && req.user.department_id !== config.department_id && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden: Department access restricted'
      });
    }

    next();
  } catch (error) {
    console.error('Authorization error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during authorization'
    });
  }
};

module.exports = authorizeMiddleware;
