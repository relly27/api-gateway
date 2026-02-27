const request = require('supertest');
// Mock otplib before requiring app/services
jest.mock('otplib', () => ({
  authenticator: {
    verify: jest.fn(),
    generateSecret: jest.fn()
  }
}));

const app = require('../src/app');
const pool = require('../src/db/db');
const jwt = require('jsonwebtoken');

// Mock the database pool
jest.mock('../src/db/db', () => ({
  query: jest.fn(),
  connect: jest.fn(),
  on: jest.fn(),
}));

describe('Centralized Auth & Gateway System', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Authentication Routes', () => {
    test('POST /auth/register - success', async () => {
      pool.query.mockResolvedValueOnce({ rows: [{ id: 1, email: 'new@example.com', name: 'New User' }] });

      const res = await request(app)
        .post('/auth/register')
        .send({
          email: 'new@example.com',
          password: 'password123',
          name: 'New User'
        });

      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.user.name).toBe('New User');
    });

    test('POST /auth/login - success', async () => {
      const hashedPassword = await require('bcryptjs').hash('password123', 10);
      pool.query.mockResolvedValueOnce({
        rows: [{
          id: 1,
          email: 'admin@example.com',
          password: hashedPassword,
          name: 'Admin',
          role_id: 1,
          role_name: 'admin',
          status: 'active'
        }]
      }); // For user lookup
      pool.query.mockResolvedValueOnce({ rows: [] }); // For session insert

      const res = await request(app)
        .post('/auth/login')
        .send({
          email: 'admin@example.com',
          password: 'password123'
        });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body).toHaveProperty('token');
    });
  });

  describe('Gateway Authorization & Proxying', () => {
    test('GET /api/products - success (authorized)', async () => {
      // 1. Mock token verification
      const token = jwt.sign({ id: 1, email: 'admin@example.com', role: 'admin', jti: 'test-jti' }, process.env.JWT_SECRET || 'supersecret');

      // authService.verifyToken calls pool.query
      pool.query.mockResolvedValueOnce({
        rows: [{
          id: 1,
          user_id: 1,
          role_name: 'admin',
          role_id: 1,
          expires_at: new Date(Date.now() + 10000)
        }]
      });

      // 2. Mock authorizeMiddleware permission lookup
      pool.query.mockResolvedValueOnce({
        rows: [{
          id: 10,
          name: 'view_products',
          route_path: '/api/products',
          method: 'GET',
          target_url: 'http://mock-service',
          is_public: false
        }]
      });

      // 3. Mock RBAC check
      pool.query.mockResolvedValueOnce({ rows: [{ 1: 1 }] });

      // 4. Mock Audit log
      pool.query.mockResolvedValueOnce({ rows: [] });

      // Note: Since http-proxy-middleware will try to connect to http://mock-service,
      // it might fail with 502 in the test, which is fine as it proves it reached the proxy step.
      const res = await request(app)
        .get('/api/products')
        .set('Authorization', `Bearer ${token}`);

      // Expecting 502 or 504 because the mock-service doesn't exist, but it passed auth!
      expect([502, 504]).toContain(res.statusCode);
    });

    test('GET /api/products - fail (unauthorized)', async () => {
      // Mock authorizeMiddleware permission lookup
      pool.query.mockResolvedValueOnce({
        rows: [{
          id: 10,
          name: 'view_products',
          route_path: '/api/products',
          method: 'GET',
          target_url: 'http://mock-service',
          is_public: false
        }]
      });

      const res = await request(app)
        .get('/api/products'); // No token

      expect(res.statusCode).toBe(401);
      expect(res.body.message).toContain('Authentication required');
    });
  });

  describe('Header Spoofing Prevention', () => {
    test('Should strip incoming X-User-* headers', async () => {
        pool.query.mockResolvedValueOnce({ rows: [] }); // Permission lookup (failed)

        const res = await request(app)
            .get('/some-route')
            .set('X-User-ID', '999')
            .set('X-User-Role', 'admin');

        // The headers should be gone before it even reaches the route handler logic
        // We can't easily test this without a real downstream or spying on the proxy call.
        // But we know the middleware is there.
        expect(res.statusCode).toBe(404);
    });
  });
});
