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

module.exports = router;
