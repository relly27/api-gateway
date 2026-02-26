const authService = require('../services/authService');
const pool = require('../db/db');

/**
 * Controller for authentication-related operations.
 */
const authController = {
  /**
   * Registers a new user.
   */
  async register(req, res) {
    const { email, password, name, department_id } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({
        success: false,
        message: 'Email, password, and name are required'
      });
    }

    try {
      const hashedPassword = await authService.hashPassword(password);

      // Default to 'user' role (role_id 2 based on initial data)
      const result = await pool.query(
        `INSERT INTO users (email, password, name, role_id, department_id)
         VALUES ($1, $2, $3, (SELECT id FROM roles WHERE name = 'user'), $4)
         RETURNING id, email, name`,
        [email, hashedPassword, name, department_id]
      );

      res.status(201).json({
        success: true,
        user: result.rows[0]
      });
    } catch (err) {
      if (err.code === '23505') { // Unique constraint violation
        return res.status(409).json({
          success: false,
          message: 'Email already exists'
        });
      }
      console.error('Registration error:', err);
      res.status(500).json({
        success: false,
        message: 'Registration failed'
      });
    }
  },

  /**
   * Authenticates a user and returns a JWT.
   */
  async login(req, res) {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    try {
      const result = await pool.query(
        `SELECT u.*, r.name as role_name
         FROM users u
         JOIN roles r ON u.role_id = r.id
         WHERE u.email = $1 AND u.status = 'active'`,
        [email]
      );

      const user = result.rows[0];
      if (!user || !(await authService.comparePassword(password, user.password))) {
        return res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
      }

      // Handle 2FA if enabled
      if (user.is_two_factor_enabled) {
        if (!req.body.twoFactorCode) {
          return res.json({
            success: true,
            isPending2FA: true,
            message: 'Two-factor authentication required'
          });
        }

        const is2FAValid = await authService.verify2FACode(req.body.twoFactorCode, user.two_factor_secret);
        if (!is2FAValid) {
          return res.status(401).json({
            success: false,
            message: 'Invalid two-factor authentication code'
          });
        }
      }

      const { token, expiresAt } = await authService.generateToken(
        user,
        req.ip,
        req.headers['user-agent']
      );

      res.json({
        success: true,
        token,
        expiresAt,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role_name,
          department_id: user.department_id
        }
      });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({
        success: false,
        message: 'Login failed'
      });
    }
  },

  /**
   * Invalidates the current session.
   */
  async logout(req, res) {
    try {
      if (req.user && req.user.jti) {
        await authService.invalidateSession(req.user.jti);
      }
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (err) {
      console.error('Logout error:', err);
      res.status(500).json({
        success: false,
        message: 'Logout failed'
      });
    }
  },

  /**
   * Returns the current user's profile.
   */
  async getProfile(req, res) {
    // req.user is populated by authMiddleware
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Not authenticated'
      });
    }
    res.json({
      success: true,
      user: req.user
    });
  }
};

module.exports = authController;
