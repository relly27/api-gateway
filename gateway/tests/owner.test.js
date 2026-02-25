const request = require('supertest');
const express = require('express');
const validateOwner = require('../middleware/owner');

describe('API Gateway - Owner Validation', () => {
  let app;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use((req, res, next) => {
      req.user = { userId: 1, email: 'test@example.com' };
      next();
    });
  });

  test('allow if userId matches', async () => {
    app.get('/profile/:userId', validateOwner('userId'), (req, res) => res.status(200).json({ ok: true }));

    const res = await request(app).get('/profile/1');
    expect(res.statusCode).toBe(200);
  });

  test('reject if userId does not match', async () => {
    app.get('/profile/:userId', validateOwner('userId'), (req, res) => res.status(200).json({ ok: true }));

    const res = await request(app).get('/profile/2');
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toBe('Forbidden: You do not own this resource');
  });

  test('check in body if not in params', async () => {
    app.post('/update', validateOwner('userId'), (req, res) => res.status(200).json({ ok: true }));

    const res = await request(app).post('/update').send({ userId: 1 });
    expect(res.statusCode).toBe(200);

    const resFail = await request(app).post('/update').send({ userId: 2 });
    expect(resFail.statusCode).toBe(403);
  });
});
