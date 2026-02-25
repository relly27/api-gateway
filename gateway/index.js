const express = require('express');
const proxy = require('express-http-proxy');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');
const authenticate = require('./middleware/auth');
const authorize = require('./middleware/authorize');
const checkDepartment = require('./middleware/department');
const validateOwner = require('./middleware/owner');
const auditRequest = require('./middleware/audit');

dotenv.config();

if (!process.env.JWT_SECRET) {
  throw new Error('FATAL ERROR: JWT_SECRET is not defined.');
}

const app = express();

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});

app.use(limiter);
app.use(auditRequest);

// Strip incoming X-User headers to prevent spoofing
app.use((req, res, next) => {
  delete req.headers['x-user-id'];
  delete req.headers['x-user-email'];
  delete req.headers['x-user-departments'];
  next();
});

const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:3001';
const EXAMPLE_SERVICE_URL = process.env.EXAMPLE_SERVICE_URL || 'http://localhost:3002';

// Auth Service Routes
const authProxy = proxy(AUTH_SERVICE_URL, {
  proxyReqPathResolver: (req) => '/auth' + req.url
});

// Public Auth Routes
app.post('/auth/register', authProxy);
app.post('/auth/login', authProxy);
app.get('/auth/methods', authProxy);
app.post('/auth/recover', authProxy);
app.post('/auth/reset-password', authProxy);
app.get('/auth/google', authProxy);
app.get('/auth/google/callback', authProxy);
app.get('/auth/github', authProxy);
app.get('/auth/github/callback', authProxy);
app.post('/auth/2fa/verify', authProxy);

// Protected Auth Routes (Require session)
app.post('/auth/2fa/setup', authenticate, authProxy);
app.post('/auth/2fa/enable', authenticate, authProxy);
app.post('/auth/logout', authenticate, authProxy);

// Protected routes
app.use('/api/example/view', authenticate, authorize('view_products'), proxy(EXAMPLE_SERVICE_URL, {
  proxyReqPathResolver: (req) => {
    return '/view' + req.url;
  },
  proxyReqOptDecorator: (proxyReqOpts, srcReq) => {
    // Pass user info to microservice via headers
    proxyReqOpts.headers['X-User-ID'] = srcReq.user.userId;
    proxyReqOpts.headers['X-User-Email'] = srcReq.user.email;
    if (srcReq.user.departments) {
      proxyReqOpts.headers['X-User-Departments'] = srcReq.user.departments.join(',');
    }
    return proxyReqOpts;
  }
}));

app.use('/api/example/create', authenticate, authorize('create_products'), checkDepartment, proxy(EXAMPLE_SERVICE_URL, {
  proxyReqPathResolver: (req) => {
    return '/create' + req.url;
  },
  proxyReqOptDecorator: (proxyReqOpts, srcReq) => {
    proxyReqOpts.headers['X-User-ID'] = srcReq.user.userId;
    proxyReqOpts.headers['X-User-Email'] = srcReq.user.email;
    if (srcReq.user.departments) {
      proxyReqOpts.headers['X-User-Departments'] = srcReq.user.departments.join(',');
    }
    return proxyReqOpts;
  }
}));

app.use('/api/example/profile/:userId', authenticate, validateOwner('userId'), proxy(EXAMPLE_SERVICE_URL, {
  proxyReqPathResolver: (req) => {
    return '/profile/' + req.params.userId;
  },
  proxyReqOptDecorator: (proxyReqOpts, srcReq) => {
    proxyReqOpts.headers['X-User-ID'] = srcReq.user.userId;
    proxyReqOpts.headers['X-User-Email'] = srcReq.user.email;
    return proxyReqOpts;
  }
}));

if (process.env.NODE_ENV !== 'test') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`API Gateway running on port ${PORT}`);
  });
}

module.exports = app;
