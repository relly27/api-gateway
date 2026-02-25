const request = require('supertest');
const express = require('express');
const auditRequest = require('../middleware/audit');
const db = require('../db');

jest.mock('../db');

describe('API Gateway - Auditing', () => {
  let app;

  beforeEach(() => {
    jest.clearAllMocks();
    app = express();
    app.use(express.json());
    app.use((req, res, next) => {
      req.user = { userId: 1, email: 'test@example.com' };
      next();
    });
    app.use(auditRequest);
  });

  test('audit log created after request', (done) => {
    app.get('/test', (req, res) => res.status(200).json({ ok: true }));

    request(app)
      .get('/test')
      .set('User-Agent', 'AuditBrowser')
      .expect(200)
      .end((err, res) => {
        if (err) return done(err);

        // Use a small timeout to allow the 'finish' event to trigger the async db call
        setTimeout(() => {
          try {
            const auditCall = db.query.mock.calls.find(call => call[0].includes('INSERT INTO audit_logs') && call[1][1] === 'API_REQUEST');
            expect(auditCall).toBeDefined();
            expect(auditCall[1][4]).toBe('AuditBrowser');
            done();
          } catch (e) {
            done(e);
          }
        }, 50);
      });
  });
});
