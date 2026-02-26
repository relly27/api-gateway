const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const pool = require('../db/db');
const crypto = require('crypto');
const { authenticator } = require('otplib');

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '2h';

const authService = {
  /**
   * Hashes a password using bcrypt.
   */
  async hashPassword(password) {
    return await bcrypt.hash(password, 10);
  },

  /**
   * Compares a plain text password with a hash.
   */
  async comparePassword(password, hash) {
    return await bcrypt.compare(password, hash);
  },

  /**
   * Generates a JWT and stores the session in the database.
   */
  async generateToken(user, ipAddress, userAgent) {
    const jti = crypto.randomUUID();
    const payload = {
      id: user.id,
      email: user.email,
      role: user.role_name,
      department_id: user.department_id,
      jti
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    // Calculate expiration date from token
    const decoded = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);

    // Save session to database for tracking and revocation
    await pool.query(
      'INSERT INTO sessions (user_id, token, jti, expires_at, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5, $6)',
      [user.id, token, jti, expiresAt, ipAddress, userAgent]
    );

    return { token, jti, expiresAt };
  },

  /**
   * Verifies a JWT and checks if the session is still active in the DB.
   */
  async verifyToken(token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);

      // Check if session exists and is not expired in DB
      const result = await pool.query(
        `SELECT s.*, u.role_id, r.name as role_name, u.department_id
         FROM sessions s
         JOIN users u ON s.user_id = u.id
         JOIN roles r ON u.role_id = r.id
         WHERE s.jti = $1 AND s.expires_at > NOW()`,
        [decoded.jti]
      );

      if (result.rows.length === 0) {
        return null;
      }

      return {
        ...decoded,
        user: result.rows[0]
      };
    } catch (err) {
      return null;
    }
  },

  /**
   * Invalidates a specific session by its JTI.
   */
  async invalidateSession(jti) {
    await pool.query('DELETE FROM sessions WHERE jti = $1', [jti]);
  },

  /**
   * Invalidates all sessions for a specific user.
   */
  async invalidateAllUserSessions(userId) {
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
  },

  /**
   * Verifies a TOTP 2FA code.
   */
  async verify2FACode(token, secret) {
    return authenticator.verify({ token, secret });
  },

  /**
   * Generates a new 2FA secret.
   */
  async generate2FASecret() {
    return authenticator.generateSecret();
  }
};

module.exports = authService;
