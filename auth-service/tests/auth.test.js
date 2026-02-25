const request = require('supertest');
const jwt = require('jsonwebtoken');

// Define JWT_SECRET before requiring app
process.env.JWT_SECRET = 'test-secret';

const app = require('../index');
const db = require('../db');

jest.mock('../db');

describe('Auth Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('POST /auth/register - success', async () => {
    db.query.mockImplementation((text, params) => {
      if (text.includes('INSERT INTO users')) {
        return { rows: [{ id: 1, email: params[0] }] };
      }
      if (text.includes('SELECT id FROM roles')) {
        return { rows: [{ id: 1 }] };
      }
      return { rows: [] };
    });

    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'test@example.com', password: 'password123' });

    expect(res.statusCode).toBe(201);
  });

  describe('Login & 2FA Flow', () => {
    test('login with 2FA enabled returns pending token', async () => {
      const passwordHash = await require('bcrypt').hash('password123', 10);
      db.query.mockResolvedValue({
        rows: [{ id: 1, email: 'test@example.com', password_hash: passwordHash, is_two_factor_enabled: true }]
      });

      const res = await request(app)
        .post('/auth/login')
        .send({ email: 'test@example.com', password: 'password123' });

      expect(res.statusCode).toBe(200);
      expect(res.body.twoFactorRequired).toBe(true);
      expect(res.body.pendingToken).toBeDefined();
    });

    test('2FA verify with valid pending token', async () => {
      const pendingToken = jwt.sign({ userId: 1, email: 'test@example.com', isPending2FA: true }, 'test-secret');
      const speakeasy = require('speakeasy');
      const secret = speakeasy.generateSecret();
      const token = speakeasy.totp({ secret: secret.base32, encoding: 'base32' });

      db.query.mockImplementation((text, params) => {
        if (text.includes('SELECT * FROM users')) {
          return { rows: [{ id: 1, email: 'test@example.com', two_factor_secret: secret.base32 }] };
        }
        return { rows: [] };
      });

      const res = await request(app)
        .post('/auth/2fa/verify')
        .send({ pendingToken, token });

      expect(res.statusCode).toBe(200);
      expect(res.body.token).toBeDefined();
    });
  });

  test('POST /auth/logout', async () => {
    const token = 'some-token';
    const res = await request(app)
      .post('/auth/logout')
      .set('Authorization', `Bearer ${token}`);

    expect(res.statusCode).toBe(200);
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('DELETE FROM sessions'), [token]);
  });
});
