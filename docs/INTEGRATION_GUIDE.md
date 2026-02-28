# Microservices Integration Guide

This guide explains how to integrate a new microservice into the centralized authentication and authorization system.

## 1. Gateway Overview

The API Gateway acts as the single entry point. It handles authentication, authorization, auditing, and header injection.

### Gateway Modes

The system supports two gateway modes:

1.  **Node.js Gateway (Default)**: Uses the built-in Express-based proxy logic in `src/routes/gateway/`. Simple to set up and ideal for low-to-medium traffic.
2.  **Nginx Gateway (Performance Mode)**: Uses Nginx as a high-performance entry point. Nginx delegates security checks to the Express service using the `auth_request` module. This is recommended for production environments.

## 2. Adding a New Microservice

To add a new microservice, you don't need to write any security code in the microservice itself. You only need to configure the routes in the Gateway's database.

### Step A: Configure the Permission

Insert a record into the `permissions` table:

```sql
INSERT INTO permissions (name, description, route_path, method, target_url, is_owner_resource, department_id)
VALUES (
    'create_order',
    'Allows creating a new order',
    '/api/orders',
    'POST',
    'http://orders-service:3002',
    FALSE,
    NULL
);
```

- `route_path`: The prefix that the gateway will match.
- `target_url`: The internal URL of your microservice.
- `is_owner_resource`: Set to `TRUE` if the user can only access their own data (expects user ID as the last segment of the path).
- `department_id`: Set to a department ID if access is restricted to a specific department.

### Step B: Assign Permission to Roles

Link the new permission to one or more roles in the `role_permissions` table:

```sql
INSERT INTO role_permissions (role_id, permission_id)
VALUES (
    (SELECT id FROM roles WHERE name = 'user'),
    (SELECT id FROM permissions WHERE name = 'create_order')
);
```

## 3. Consuming User Context in Microservices

Your microservices will receive the following headers from the Gateway for every authenticated request:

| Header | Description |
|--------|-------------|
| `X-User-Id` | The unique ID of the authenticated user. |
| `X-User-Email` | The user's email address. |
| `X-User-Role` | The name of the user's role (e.g., 'admin', 'user'). |
| `X-User-Department-Id` | The ID of the user's department (if assigned). |

### Example (Node.js/Express):

```javascript
app.post('/api/orders', (req, res) => {
  const userId = req.headers['x-user-id'];
  const userRole = req.headers['x-user-role'];

  // Business logic here...
  console.log(`Processing order for user ${userId}`);
  res.json({ success: true });
});
```

## 4. Security Best Practices

1.  **Trust the Gateway**: Configure your microservices to only accept traffic from the Gateway's IP or a private network.
2.  **No Local Auth**: Remove any JWT validation or local user tables from your microservices.
3.  **Owner Validation**: Use `is_owner_resource: TRUE` for routes like `/api/users/:id`. The Gateway will automatically block users from accessing IDs other than their own.
4.  **Public Routes**: Use `is_public: TRUE` in the `permissions` table for routes that don't require authentication (e.g., public catalogs).
