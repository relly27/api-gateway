# Centralized Authentication and Authorization System

A robust, scalable architectural solution for centralizing security concerns across a microservices landscape.

## Features

- **Centralized API Gateway**: Single entry point for all microservices.
- **Shared Security Database**: Unified management of Users, Roles, Permissions, Sessions, and Audit Logs.
- **Dynamic Routing**: Configure routes and targets directly in the database.
- **Granular RBAC**: Role-based access control per route and HTTP method.
- **Owner Validation**: Automatic enforcement of resource ownership.
- **Department Restrictions**: Secure access based on organizational departments.
- **Advanced Auditing**: Complete history of logins, registrations, and proxied requests.
- **2FA Support**: Built-in TOTP two-factor authentication.
- **Header Spoofing Protection**: Automatic stripping of unauthorized security headers.

## Getting Started

### Prerequisites

- Node.js (v18+)
- PostgreSQL

### Installation

1.  Clone the repository.
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Configure environment variables:
    ```bash
    cp env.example .env
    # Edit .env with your database credentials and JWT secret
    ```
4.  Run migrations:
    ```bash
    npm run migrate
    ```

### Running the System

```bash
npm start
```

## Documentation

- [Microservices Integration Guide](./docs/INTEGRATION_GUIDE.md): Learn how to add and secure new services.
- [Database Schema](./src/db/migration/up.sql): Detailed table definitions.

## Project Structure

- `src/app.js`: Main application and gateway entry point.
- `src/routes/gateway/`: Dynamic proxy logic and routing.
- `src/middlewares/`: Security middlewares (Auth, Authorize, Audit).
- `src/services/`: Core logic for auth and security.
- `src/controllers/`: Local authentication handlers.

## License

ISC
