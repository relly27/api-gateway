const request = require('supertest');
const express = require('express');
const authorize = require('../middleware/authorize');
const db = require('../db');

jest.mock('../db');

describe('API Gateway - Authorization', () => {
  let app;

  beforeEach(() => {
    jest.clearAllMocks();
    app = express();
    app.use(express.json());
    // Mock req.user that comes from authenticate middleware
    app.use((req, res, next) => {
      req.user = { userId: 1, email: 'test@example.com' };
      next();
    });
  });

  test('authorize success - has permission', async () => {
    db.query.mockImplementation((text, params) => {
      if (text.includes('permissions p')) {
        return { rows: [{ name: 'view_products' }] };
      }
      return { rows: [] };
    });

    app.get('/test', authorize('view_products'), (req, res) => res.status(200).json({ ok: true }));

    const res = await request(app).get('/test');
    expect(res.statusCode).toBe(200);
  });

  test('authorize success - is admin', async () => {
    db.query.mockImplementation((text, params) => {
      if (text.includes('roles r')) {
        return { rows: [{ name: 'admin' }] };
      }
      return { rows: [] };
    });

    app.get('/test-admin', authorize('any_permission'), (req, res) => res.status(200).json({ ok: true }));

    const res = await request(app).get('/test-admin');
    expect(res.statusCode).toBe(200);
  });

  test('authorize failure - forbidden', async () => {
    db.query.mockResolvedValue({ rows: [] });

    app.get('/test-fail', authorize('secret_permission'), (req, res) => res.status(200).json({ ok: true }));

    const res = await request(app).get('/test-fail');
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toBe('Forbidden: Insufficient permissions');
  });
});
