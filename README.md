# Centralized Authentication and Authorization System

This project provides a robust architectural solution to centralize security concerns for Express-based microservices.

## Key Features

- **Single Entry Point**: Centralized API Gateway handles all security.
- **Shared Security Database**: All users, roles, permissions, sessions, and audit logs reside in a single PostgreSQL database.
- **Complete Auth Service**:
  - Email/Password login with Bcrypt hashing.
  - OAuth (Google, GitHub) via Passport.js.
  - Two-Factor Authentication (2FA) with TOTP/QR Codes.
  - Password recovery via email (simulated).
  - "Remember me" (30-day long-lived sessions).
- **Flexible Authorization**:
  - Granular RBAC (Permissions-based).
  - Department-based data isolation.
  - Resource owner validation.
- **Auditing and Scalability**:
  - Detailed audit logging of all security events and API requests.
  - Rate limiting on the gateway.
  - Easy integration of new microservices.

## Project Structure

- `/gateway`: The entry point and security enforcer.
- `/auth-service`: Handles registration, login, 2FA, OAuth, and recovery.
- `/example-service`: A sample microservice showing security-free business logic.
- `/database`: Contains the shared schema (`init.sql`).
- `/tests`: Integration tests for the full flow.

## Getting Started

1.  **Database**: The system uses PostgreSQL. See `database/init.sql` for the schema.
2.  **Environment Variables**: Each service requires a `.env` file (see Docker Compose for required variables like `JWT_SECRET` and `DATABASE_URL`).
3.  **Docker**: Run `docker compose up` to start the entire system.

## Integration

Refer to [GUIDE.md](./GUIDE.md) for instructions on how to add new microservices and manage permissions.
