const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const otplib = require('otplib');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const { query } = require('../database/db');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());
app.use(morgan('dev'));
app.use(passport.initialize());

app.get('/test', (req, res) => res.send('ok'));

const JWT_SECRET = process.env.JWT_SECRET || 'secret';

// Passport Strategies
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID || 'google-id',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'google-secret',
    callbackURL: "/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let result = await query("SELECT * FROM auth_providers WHERE provider = ? AND provider_id = ?", ['google', profile.id]);
      let user;
      if (result.rows.length > 0) {
        const userRes = await query("SELECT * FROM users WHERE id = ?", [result.rows[0].user_id]);
        user = userRes.rows[0];
      } else {
        // Create user
        const newUser = await query(
          "INSERT INTO users (username, email, status) VALUES (?, ?, ?)",
          [profile.displayName, profile.emails[0].value, 'active']
        );
        await query(
          "INSERT INTO auth_providers (user_id, provider, provider_id) VALUES (?, ?, ?)",
          [newUser.lastID, 'google', profile.id]
        );
        const userRes = await query("SELECT * FROM users WHERE id = ?", [newUser.lastID]);
        user = userRes.rows[0];
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID || 'github-id',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || 'github-secret',
    callbackURL: "/auth/github/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let result = await query("SELECT * FROM auth_providers WHERE provider = ? AND provider_id = ?", ['github', profile.id]);
      let user;
      if (result.rows.length > 0) {
        const userRes = await query("SELECT * FROM users WHERE id = ?", [result.rows[0].user_id]);
        user = userRes.rows[0];
      } else {
        const newUser = await query(
          "INSERT INTO users (username, email, status) VALUES (?, ?, ?)",
          [profile.username, profile.emails ? profile.emails[0].value : `${profile.username}@github.com`, 'active']
        );
        await query(
          "INSERT INTO auth_providers (user_id, provider, provider_id) VALUES (?, ?, ?)",
          [newUser.lastID, 'github', profile.id]
        );
        const userRes = await query("SELECT * FROM users WHERE id = ?", [newUser.lastID]);
        user = userRes.rows[0];
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// Helper to generate tokens
const generateTokens = (user) => {
  const jti = uuidv4();
  const accessToken = jwt.sign(
    { id: user.id, email: user.email, username: user.username, jti },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
  const refreshToken = jwt.sign(
    { id: user.id, jti },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  return { accessToken, refreshToken };
};

// Register
app.post('/register', async (req, res) => {
  const { username, email, password, department_id } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await query(
      "INSERT INTO users (username, email, password_hash, department_id) VALUES (?, ?, ?, ?)",
      [username, email, hashedPassword, department_id]
    );
    res.status(201).json({ message: 'User registered successfully', userId: result.lastID });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await query("SELECT * FROM users WHERE email = ?", [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.two_factor_enabled) {
      // Return a temporary token for 2FA verification
      const tempToken = jwt.sign({ id: user.id, isPending2FA: true }, JWT_SECRET, { expiresIn: '5m' });
      return res.json({ isPending2FA: true, tempToken });
    }

    const { accessToken, refreshToken } = generateTokens(user);

    // Store session
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);
    await query(
      "INSERT INTO sessions (user_id, token, refresh_token, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
      [user.id, accessToken, refreshToken, expiresAt.toISOString(), req.ip, req.get('user-agent')]
    );

    res.json({ accessToken, refreshToken, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Refresh Token
app.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: 'Refresh token required' });

  try {
    const payload = jwt.verify(refreshToken, JWT_SECRET);
    const result = await query("SELECT * FROM sessions WHERE refresh_token = ? AND is_revoked = 0", [refreshToken]);
    const session = result.rows[0];

    if (!session) return res.status(401).json({ error: 'Invalid or revoked refresh token' });

    const userResult = await query("SELECT * FROM users WHERE id = ?", [payload.id]);
    const user = userResult.rows[0];

    const tokens = generateTokens(user);

    // Update session with new access token and new refresh token (rotation)
    await query(
      "UPDATE sessions SET token = ?, refresh_token = ? WHERE id = ?",
      [tokens.accessToken, tokens.refreshToken, session.id]
    );

    res.json(tokens);
  } catch (err) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// Logout
app.post('/logout', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(400).json({ error: 'Authorization header required' });
  const token = authHeader.split(' ')[1];

  try {
    await query("UPDATE sessions SET is_revoked = 1 WHERE token = ?", [token]);
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get profile (me)
app.get('/me', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Authorization header required' });
  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Also check if session is valid
    const sessionResult = await query("SELECT * FROM sessions WHERE token = ? AND is_revoked = 0", [token]);
    if (sessionResult.rows.length === 0) {
      return res.status(401).json({ error: 'Session expired or revoked' });
    }

    const result = await query(`
      SELECT u.id, u.username, u.email, d.name as department
      FROM users u
      LEFT JOIN departments d ON u.department_id = d.id
      WHERE u.id = ?
    `, [payload.id]);

    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    // Get roles
    const rolesResult = await query(`
      SELECT r.name
      FROM roles r
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = ?
    `, [payload.id]);

    const user = result.rows[0];
    user.roles = rolesResult.rows.map(r => r.name);

    res.json(user);
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// 2FA Setup
app.post('/2fa/setup', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Authorization header required' });
  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const secret = otplib.generateSecret();
    const userResult = await query("SELECT email FROM users WHERE id = ?", [payload.id]);
    const email = userResult.rows[0].email;

    const otpauth = otplib.generateURI({ label: email, issuer: 'CentralizedAuth', secret });
    const qrCode = await QRCode.toDataURL(otpauth);

    await query("UPDATE users SET two_factor_secret = ? WHERE id = ?", [secret, payload.id]);

    res.json({ secret, qrCode });
  } catch (err) {
    console.error('2FA Setup error:', err);
    res.status(401).json({ error: 'Invalid token', details: err.message });
  }
});

// 2FA Verify and Enable
app.post('/2fa/verify', async (req, res) => {
  const { code } = req.body;
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Authorization header required' });
  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const userResult = await query("SELECT two_factor_secret FROM users WHERE id = ?", [payload.id]);
    const secret = userResult.rows[0].two_factor_secret;

    const isValid = await otplib.verify({ token: code, secret });
    if (!isValid) return res.status(400).json({ error: 'Invalid 2FA code' });

    await query("UPDATE users SET two_factor_enabled = 1 WHERE id = ?", [payload.id]);
    res.json({ message: '2FA enabled successfully' });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// 2FA Login
app.post('/2fa/login', async (req, res) => {
  const { code, tempToken } = req.body;
  try {
    const payload = jwt.verify(tempToken, JWT_SECRET);
    if (!payload.isPending2FA) return res.status(400).json({ error: 'Invalid token for 2FA' });

    const userResult = await query("SELECT * FROM users WHERE id = ?", [payload.id]);
    const user = userResult.rows[0];

    const isValid = await otplib.verify({ token: code, secret: user.two_factor_secret });
    if (!isValid) {
      console.log('2FA login failed: Invalid code', { code, secret: user.two_factor_secret });
      return res.status(400).json({ error: 'Invalid 2FA code' });
    }

    const { accessToken, refreshToken } = generateTokens(user);

    // Store session
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);
    await query(
      "INSERT INTO sessions (user_id, token, refresh_token, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
      [user.id, accessToken, refreshToken, expiresAt.toISOString(), req.ip, req.get('user-agent')]
    );

    res.json({ accessToken, refreshToken, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    console.error('2FA login catch error:', err);
    res.status(401).json({ error: 'Invalid or expired temporary token', details: err.message });
  }
});

// OAuth Routes
app.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
  const { accessToken, refreshToken } = generateTokens(req.user);
  res.json({ accessToken, refreshToken, user: req.user });
});

app.get('/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/github/callback', passport.authenticate('github', { session: false }), (req, res) => {
  const { accessToken, refreshToken } = generateTokens(req.user);
  res.json({ accessToken, refreshToken, user: req.user });
});

const PORT = process.env.PORT || 3001;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Auth Service running on port ${PORT}`);
  });
}

module.exports = app;
