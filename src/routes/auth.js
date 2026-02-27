const express = require('express');
const authController = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');
const auditMiddleware = require('../middlewares/auditMiddleware');

const router = express.Router();

/**
 * @route POST /auth/register
 * @desc Register a new user
 * @access Public
 */
router.post('/register', auditMiddleware, authController.register);

/**
 * @route POST /auth/login
 * @desc Login a user and return a JWT
 * @access Public
 */
router.post('/login', auditMiddleware, authController.login);

/**
 * @route POST /auth/logout
 * @desc Logout the current user (invalidate session)
 * @access Private
 */
router.post('/logout', authMiddleware, auditMiddleware, authController.logout);

/**
 * @route GET /auth/profile
 * @desc Get the current user's profile
 * @access Private
 */
router.get('/profile', authMiddleware, auditMiddleware, authController.getProfile);

/**
 * @route GET /auth/verify
 * @desc Verify session and authorize route (for Nginx auth_request)
 * @access Private/Public (depends on route)
 */
const authorizeMiddleware = require('../middlewares/authorizeMiddleware');

router.get('/verify', authMiddleware, authorizeMiddleware, auditMiddleware, (req, res) => {
  // If we reach here, it means both auth and authorize passed
  const { gatewayConfig, user } = req;

  // Set headers that Nginx can extract
  if (gatewayConfig && gatewayConfig.target_url) {
    res.setHeader('X-Target-Url', gatewayConfig.target_url);
  }

  if (user) {
    res.setHeader('X-User-Id', user.id.toString());
    res.setHeader('X-User-Email', user.email);
    res.setHeader('X-User-Role', user.role);
    res.setHeader('X-User-Department-Id', user.department_id ? user.department_id.toString() : '');
  }

  res.status(200).send('OK');
});

module.exports = router;
