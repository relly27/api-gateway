const express = require('express');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { query } = require('../database/db');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

const JWT_SECRET = process.env.JWT_SECRET || 'secret';

// Audit Logging Middleware
async function auditLog(req, res, next) {
  const startTime = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const userId = req.user ? req.user.id : null;
    const action = `${req.method} ${req.originalUrl}`;
    const status = res.statusCode >= 400 ? 'failure' : 'success';

    const logData = [
      userId,
      action,
      req.path,
      status,
      req.ip,
      req.get('user-agent'),
      JSON.stringify({
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        duration: `${duration}ms`
      })
    ];
    query(`
      INSERT INTO audit_logs (user_id, action, resource, status, ip_address, user_agent, details)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, logData).catch(err => console.error('Audit log failed:', err));
  });
  next();
};

const app = express();

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

app.use(cors());
app.use(helmet());
app.use(morgan('dev'));

// 1. Strip incoming security headers
app.use((req, res, next) => {
  delete req.headers['x-user-id'];
  delete req.headers['x-user-email'];
  delete req.headers['x-user-departments'];
  next();
});

// 2. Add Audit Logging
app.use(express.json());
app.use(auditLog);

// Proxy configurations
const proxyOptions = {
  changeOrigin: true,
  on: {
    proxyReq: (proxyReq, req) => {
      fixRequestBody(proxyReq, req);
      if (req.user) {
        proxyReq.setHeader('X-User-ID', req.user.id || '');
        proxyReq.setHeader('X-User-Email', req.user.email || '');
        proxyReq.setHeader('X-User-Departments', req.user.department || '');
      }
    }
  }
};

// Routes
app.use('/auth', createProxyMiddleware({
  target: 'http://localhost:3001',
  pathRewrite: {
    '^/auth': ''
  },
  ...proxyOptions
}));

// Users route demo
app.use('/api/users', authenticateJWT, authorize, (req, res) => {
  res.json({ message: 'User data' });
});

// Protected route demo
app.use('/api/products', authenticateJWT, authorize, createProxyMiddleware({
  target: 'http://localhost:3002',
  pathRewrite: {
    '^/api/products': ''
  },
  ...proxyOptions
}));

// JWT Validation Middleware
async function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    try {
      const user = jwt.verify(token, JWT_SECRET);
      const sessionResult = await query("SELECT * FROM sessions WHERE token = ? AND is_revoked = 0", [token]);
      if (sessionResult.rows.length === 0) return res.status(401).json({ error: 'Session expired' });

      const userDetails = await query(`
        SELECT u.id, u.email, d.name as department
        FROM users u
        LEFT JOIN departments d ON u.department_id = d.id
        WHERE u.id = ?
      `, [user.id]);

      req.user = userDetails.rows.length > 0 ? userDetails.rows[0] : user;
      next();
    } catch (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
  } else {
    res.status(401).json({ error: 'Authorization header missing' });
  }
};

// RBAC Middleware
async function authorize(req, res, next) {
  const { id: userId } = req.user;
  const { method, originalUrl: resource } = req;
  try {
    const permissionsResult = await query(`
      SELECT p.* FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      JOIN user_roles ur ON rp.role_id = ur.role_id
      WHERE ur.user_id = ? AND p.method = ?
    `, [userId, method]);

    const permissions = permissionsResult.rows;

    // 1. Check for exact match or wildcard
    let allowed = permissions.some(p => p.resource === '*' || p.resource === resource);

    // 2. Check for prefix match with owner validation
    if (!allowed) {
      for (const p of permissions) {
        if (p.resource !== '*' && resource.startsWith(p.resource)) {
          if (p.is_owner_resource) {
            // Check if the resource URL contains the user ID as a parameter
            // e.g., /api/users/123 or /api/profiles/123
            const urlParts = resource.split('/');
            if (urlParts.includes(userId.toString())) {
              allowed = true;
              break;
            }
          } else {
            allowed = true;
            break;
          }
        }
      }
    }

    if (!allowed) {
      return res.status(403).json({ error: 'Access denied: insufficient permissions' });
    }

    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

const PORT = process.env.GATEWAY_PORT || 3000;
app.listen(PORT, () => console.log(`API Gateway running on port ${PORT}`));
