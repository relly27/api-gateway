const request = require('supertest');
const app = require('../src/app');
const pool = require('../src/db/db');
const jwt = require('jsonwebtoken');

// Mock the database pool
jest.mock('../src/db/db', () => ({
  query: jest.fn(),
  connect: jest.fn(),
  on: jest.fn(),
}));

describe('Nginx Auth Request Verify Endpoint', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('GET /auth/verify - success with valid token and permission', async () => {
    const token = jwt.sign({ id: 1, email: 'admin@example.com', role: 'admin', jti: 'test-jti' }, process.env.JWT_SECRET || 'supersecret');

    // 1. Mock authService.verifyToken via pool.query
    pool.query.mockResolvedValueOnce({
      rows: [{
        id: 1,
        user_id: 1,
        role_name: 'admin',
        role_id: 1,
        expires_at: new Date(Date.now() + 10000)
      }]
    });

    // 2. Mock authorizeMiddleware permission lookup (using X-Original headers)
    pool.query.mockResolvedValueOnce({
      rows: [{
        id: 10,
        name: 'view_products',
        route_path: '/api/products',
        method: 'GET',
        target_url: 'http://products-service',
        is_public: false
      }]
    });

    // 3. Mock RBAC check
    pool.query.mockResolvedValueOnce({ rows: [{ 1: 1 }] });

    // 4. Mock Audit log
    pool.query.mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .get('/auth/verify')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Original-URI', '/api/products')
      .set('X-Original-Method', 'GET');

    expect(res.statusCode).toBe(200);
    expect(res.headers['x-target-url']).toBe('http://products-service');
    expect(res.headers['x-user-id']).toBe('1');
    expect(res.headers['x-user-role']).toBe('admin');
    expect(res.text).toBe('OK');
  });

  test('GET /auth/verify - fail with invalid permission', async () => {
    const token = jwt.sign({ id: 1, email: 'user@example.com', role: 'user', jti: 'test-jti' }, process.env.JWT_SECRET || 'supersecret');

    // 1. Mock authService.verifyToken via pool.query
    pool.query.mockResolvedValueOnce({
      rows: [{
        id: 1,
        user_id: 1,
        role_name: 'user',
        role_id: 2,
        expires_at: new Date(Date.now() + 10000)
      }]
    });

    // 2. Mock authorizeMiddleware permission lookup
    pool.query.mockResolvedValueOnce({
      rows: [{
        id: 11,
        name: 'admin_only',
        route_path: '/admin',
        method: 'GET',
        target_url: 'http://admin-service',
        is_public: false
      }]
    });

    // 3. Mock RBAC check (fail for non-admin)
    pool.query.mockResolvedValueOnce({ rows: [] });

    // 4. Mock Audit log
    pool.query.mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .get('/auth/verify')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Original-URI', '/admin')
      .set('X-Original-Method', 'GET');

    expect(res.statusCode).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('Insufficient permissions');
  });
});
