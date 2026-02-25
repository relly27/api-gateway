const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const db = require('../db');
const authenticate = require('../middleware/auth');
const router = express.Router();

if (!process.env.JWT_SECRET) {
  throw new Error('FATAL ERROR: JWT_SECRET is not defined.');
}

// Register a new user
router.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await db.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email, passwordHash]
    );

    // Assign default 'user' role
    const user = result.rows[0];
    const roleResult = await db.query('SELECT id FROM roles WHERE name = $1', ['user']);
    if (roleResult.rows.length > 0) {
      await db.query('INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)', [user.id, roleResult.rows[0].id]);
    }

    // Log the action
    await db.query(
      'INSERT INTO audit_logs (user_id, action, details) VALUES ($1, $2, $3)',
      [user.id, 'USER_REGISTERED', JSON.stringify({ email: user.email })]
    );

    res.status(201).json({ message: 'User registered successfully', user });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login a user
router.post('/login', async (req, res) => {
  const { email, password, rememberMe } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      await db.query(
        'INSERT INTO audit_logs (user_id, action, details, ip_address, device_info) VALUES ($1, $2, $3, $4, $5)',
        [user.id, 'LOGIN_FAILED', JSON.stringify({ reason: 'Invalid password' }), req.ip, req.headers['user-agent']]
      );
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if 2FA is enabled
    if (user.is_two_factor_enabled) {
      const pendingToken = jwt.sign(
        { userId: user.id, email: user.email, isPending2FA: true },
        process.env.JWT_SECRET,
        { expiresIn: '5m' }
      );
      return res.json({
        message: '2FA required',
        twoFactorRequired: true,
        pendingToken
      });
    }

    // Generate JWT
    const expiresIn = rememberMe ? '30d' : '24h';
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn }
    );

    // Calculate expiration date
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + (rememberMe ? 30 : 1));

    // Save session
    await db.query(
      'INSERT INTO sessions (user_id, token, expires_at, ip_address, device_info) VALUES ($1, $2, $3, $4, $5)',
      [user.id, token, expiresAt, req.ip, req.headers['user-agent']]
    );

    // Log the action
    await db.query(
      'INSERT INTO audit_logs (user_id, action, details, ip_address, device_info) VALUES ($1, $2, $3, $4, $5)',
      [user.id, 'LOGIN_SUCCESSFUL', JSON.stringify({ method: 'password' }), req.ip, req.headers['user-agent']]
    );

    res.json({ message: 'Login successful', token, user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Detect available login methods for a user
router.get('/methods', async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const userResult = await db.query('SELECT id, is_two_factor_enabled FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.json({ methods: ['password', 'google', 'github'] }); // Return all for privacy or defaults
    }

    const user = userResult.rows[0];
    const providersResult = await db.query(
      'SELECT p.name FROM providers p JOIN user_providers up ON p.id = up.provider_id WHERE up.user_id = $1',
      [user.id]
    );

    const methods = ['password'];
    providersResult.rows.forEach(p => methods.push(p.name));

    res.json({
      methods,
      isTwoFactorEnabled: user.is_two_factor_enabled
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OAuth Routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/login' }),
  async (req, res) => {
    // Successful authentication, generate token
    const user = req.user;
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Save session
    await db.query(
      'INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, token, new Date(Date.now() + 24 * 60 * 60 * 1000)]
    );

    res.json({ message: 'Login successful', token, user: { id: user.id, email: user.email } });
  }
);

router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));

router.get('/github/callback',
  passport.authenticate('github', { session: false, failureRedirect: '/login' }),
  async (req, res) => {
    const user = req.user;
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Save session
    await db.query(
      'INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, token, new Date(Date.now() + 24 * 60 * 60 * 1000)]
    );

    res.json({ message: 'Login successful', token, user: { id: user.id, email: user.email } });
  }
);

// 2FA Setup - Generate Secret
router.post('/2fa/setup', authenticate, async (req, res) => {
  const userId = req.user.userId;

  try {
    const secret = speakeasy.generateSecret({ name: 'CentralizedAuthSystem' });

    await db.query('UPDATE users SET two_factor_secret = $1 WHERE id = $2', [secret.base32, userId]);

    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
    res.json({ secret: secret.base32, qrCode: qrCodeUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 2FA Verify and Enable
router.post('/2fa/enable', authenticate, async (req, res) => {
  const userId = req.user.userId;
  const { token } = req.body;

  try {
    const userResult = await db.query('SELECT two_factor_secret FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const secret = userResult.rows[0].two_factor_secret;
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token
    });

    if (verified) {
      await db.query('UPDATE users SET is_two_factor_enabled = TRUE WHERE id = $1', [userId]);
      res.json({ message: '2FA enabled successfully' });
    } else {
      res.status(400).json({ error: 'Invalid 2FA token' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 2FA Verify during Login
router.post('/2fa/verify', async (req, res) => {
  const { pendingToken, token } = req.body;

  if (!pendingToken || !token) {
    return res.status(400).json({ error: 'pendingToken and token are required' });
  }

  try {
    const decoded = jwt.verify(pendingToken, process.env.JWT_SECRET);
    if (!decoded.isPending2FA) {
      return res.status(400).json({ error: 'Invalid pendingToken' });
    }

    const userId = decoded.userId;
    const userResult = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    const verified = speakeasy.totp.verify({
      secret: user.two_factor_secret,
      encoding: 'base32',
      token
    });

    if (verified) {
      const jwtToken = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      await db.query(
        'INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)',
        [user.id, jwtToken, new Date(Date.now() + 24 * 60 * 60 * 1000)]
      );

      res.json({ message: 'Login successful', token: jwtToken, user: { id: user.id, email: user.email } });
    } else {
      res.status(400).json({ error: 'Invalid 2FA token' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Password Recovery Request
router.post('/recover', async (req, res) => {
  const { email } = req.body;

  try {
    const userResult = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      // Don't reveal if user exists or not for security
      return res.json({ message: 'If that email is registered, you will receive a recovery link shortly.' });
    }

    const user = userResult.rows[0];
    const token = crypto.randomBytes(32).toString('hex');

    await db.query('UPDATE users SET recovery_token = $1 WHERE id = $2', [token, user.id]);

    // Simulate sending email
    console.log(`Sending recovery email to ${email} with token: ${token}`);

    // Log the action
    await db.query(
      'INSERT INTO audit_logs (user_id, action, details) VALUES ($1, $2, $3)',
      [user.id, 'PASSWORD_RECOVERY_REQUESTED', JSON.stringify({ email })]
    );

    res.json({ message: 'If that email is registered, you will receive a recovery link shortly.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset Password
router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const userResult = await db.query('SELECT id FROM users WHERE recovery_token = $1', [token]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired recovery token' });
    }

    const user = userResult.rows[0];
    const passwordHash = await bcrypt.hash(newPassword, 10);

    await db.query(
      'UPDATE users SET password_hash = $1, recovery_token = NULL WHERE id = $2',
      [passwordHash, user.id]
    );

    // Log the action
    await db.query(
      'INSERT INTO audit_logs (user_id, action, details) VALUES ($1, $2, $3)',
      [user.id, 'PASSWORD_RESET_SUCCESSFUL', null]
    );

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout
router.post('/logout', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(400).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    await db.query('DELETE FROM sessions WHERE token = $1', [token]);
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
