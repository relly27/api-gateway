const request = require('supertest');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'test-secret';

const app = require('../index');
const db = require('../db');

jest.mock('../db');

describe('API Gateway - Authentication', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('Protected route - success', async () => {
    const token = jwt.sign({ userId: 1, email: 'test@example.com' }, 'test-secret');
    db.query.mockResolvedValue({ rows: [{ id: 1, token, user_id: 1 }] });

    const res = await request(app)
      .get('/api/example/view')
      .set('Authorization', `Bearer ${token}`);

    expect(res.statusCode).not.toBe(401);
  });

  test('Header stripping - spoofing prevention', async () => {
    const token = jwt.sign({ userId: 1, email: 'test@example.com' }, 'test-secret');
    db.query.mockResolvedValue({ rows: [{ id: 1, token, user_id: 1 }] });

    // Mock a target that checks headers
    // Actually, we can check if the headers are deleted in a middleware
    app.get('/test-headers', (req, res) => {
        res.json({
            userId: req.headers['x-user-id'],
            spoofed: req.headers['x-spoofed']
        });
    });

    const res = await request(app)
      .get('/test-headers')
      .set('Authorization', `Bearer ${token}`)
      .set('X-User-ID', '999') // Attempt to spoof
      .set('X-Spoofed', 'yes');

    // Should be undefined because we deleted it in gateway/index.js
    expect(res.body.userId).toBeUndefined();
    expect(res.body.spoofed).toBe('yes');
  });
});
