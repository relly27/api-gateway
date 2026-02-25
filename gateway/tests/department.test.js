const request = require('supertest');
const express = require('express');
const checkDepartment = require('../middleware/department');
const db = require('../db');

jest.mock('../db');

describe('API Gateway - Department Restrictions', () => {
  let app;

  beforeEach(() => {
    jest.clearAllMocks();
    app = express();
    app.use(express.json());
    app.use((req, res, next) => {
      req.user = { userId: 1, email: 'test@example.com' };
      next();
    });
  });

  test('fetch departments and pass to next', async () => {
    db.query.mockResolvedValue({ rows: [{ id: 101, name: 'Sales' }] });

    app.get('/test', checkDepartment, (req, res) => {
      expect(req.user.departments).toContain(101);
      res.status(200).json({ ok: true });
    });

    const res = await request(app).get('/test');
    expect(res.statusCode).toBe(200);
  });

  test('reject if deptId in query does not match user departments', async () => {
    db.query.mockImplementation((text, params) => {
      if (text.includes('user_departments')) {
        return { rows: [{ id: 101, name: 'Sales' }] };
      }
      if (text.includes('roles r')) {
        return { rows: [] }; // Not admin
      }
      return { rows: [] };
    });

    app.get('/test-dept', checkDepartment, (req, res) => res.status(200).json({ ok: true }));

    const res = await request(app).get('/test-dept').query({ deptId: 102 });
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toBe('Forbidden: You do not belong to this department');
  });

  test('allow if deptId in query matches user departments', async () => {
    db.query.mockResolvedValue({ rows: [{ id: 101, name: 'Sales' }] });

    app.get('/test-dept-ok', checkDepartment, (req, res) => res.status(200).json({ ok: true }));

    const res = await request(app).get('/test-dept-ok').query({ deptId: 101 });
    expect(res.statusCode).toBe(200);
  });
});
