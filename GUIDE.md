# Developer Guide: Integrating New Microservices

This guide explains how to add a new microservice to the centralized authentication and authorization system.

## 1. Gateway Configuration

To add a new microservice, you need to register its routes in `gateway/index.js`.

### Basic Proxying (Public)
If the service is public, just add a proxy rule:

```javascript
app.use('/api/public-service', proxy('http://public-service:PORT'));
```

### Protected Proxying (Private)
If the service requires authentication and authorization, use the following middlewares:

```javascript
const authenticate = require('./middleware/auth');
const authorize = require('./middleware/authorize');
const checkDepartment = require('./middleware/department');
const validateOwner = require('./middleware/owner');

app.use('/api/my-service',
  authenticate,                       // Validates JWT and session
  authorize('my_permission'),         // Checks granular RBAC
  checkDepartment,                    // (Optional) Isolates by department
  proxy('http://my-service:PORT', {
    proxyReqOptDecorator: (proxyReqOpts, srcReq) => {
      // Pass user context to the microservice
      proxyReqOpts.headers['X-User-ID'] = srcReq.user.userId;
      proxyReqOpts.headers['X-User-Email'] = srcReq.user.email;
      if (srcReq.user.departments) {
        proxyReqOpts.headers['X-User-Departments'] = srcReq.user.departments.join(',');
      }
      return proxyReqOpts;
    }
  })
);
```

## 2. Microservice Implementation

Microservices **should not** implement any authentication or authorization logic. They simply rely on the headers passed by the Gateway:

- `X-User-ID`: The unique ID of the authenticated user.
- `X-User-Email`: The user's email.
- `X-User-Departments`: A comma-separated list of department IDs the user belongs to.

Example in Express:

```javascript
app.get('/data', (req, res) => {
  const userId = req.headers['x-user-id'];
  // Business logic here...
  res.json({ message: 'Success', forUser: userId });
});
```

## 3. Database Permissions

Ensure the required permissions and roles are defined in the `permissions` and `role_permissions` tables of the security database.

```sql
INSERT INTO permissions (name, description) VALUES ('my_permission', 'Allows access to my service');
INSERT INTO role_permissions (role_id, permission_id) VALUES (ROLE_ID, PERMISSION_ID);
```

## 4. Summary of Available Security Middlewares

| Middleware | Description |
|---|---|
| `authenticate` | Verifies JWT signature and checks if the session exists in the database. Blocks if `isPending2FA` is true. |
| `authorize(perm)` | Checks if the user has the specified permission (or is an 'admin'). |
| `checkDepartment` | Fetches user departments and verifies access if `deptId` is in the request. |
| `validateOwner(idParam)` | Ensures the user is only accessing their own resources by comparing IDs. |
| `auditRequest` | (Global) Automatically logs all requests, status codes, and durations. |
| `limiter` | (Global) Applies rate limiting per IP. |
