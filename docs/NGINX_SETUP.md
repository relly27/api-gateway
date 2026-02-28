# Nginx API Gateway Setup Guide

This guide explains how to use Nginx as a high-performance API Gateway for this system.

## 1. How it Works

The Nginx gateway utilizes the `auth_request` module to centralize security.

1.  **Request Arrival**: A client sends an HTTP/HTTPS request to Nginx.
2.  **Authentication Subrequest**: Nginx sends an internal subrequest (`GET /auth/verify`) to the Node.js Auth Service.
3.  **Validation**: The Auth Service validates the JWT session and checks RBAC permissions.
4.  **Security Response**:
    - If valid, the Auth Service returns `200 OK` along with user context and the target microservice URL in headers.
    - If invalid, it returns `401 Unauthorized` or `403 Forbidden`.
5.  **Proxying**: If authorized, Nginx extracts the `X-Target-Url` and proxy-passes the original request to the destination microservice, injecting user context headers (`X-User-ID`, etc.).

## 2. Automatic Configuration

A Bash script is provided to automate the setup on Debian-based systems.

### Steps:

1.  **Ensure the Auth Service is running**:
    ```bash
    npm start
    ```
2.  **Run the configuration script**:
    ```bash
    sudo ./configure-nginx-gateway.sh
    ```

The script will:
- Install Nginx if it's missing.
- Create a configuration file at `/etc/nginx/sites-available/api-gateway`.
- Link it to `/etc/nginx/sites-enabled/`.
- Restart Nginx.

## 3. Manual Configuration Details

If you're using a different OS or a custom Nginx setup, ensure the following logic is implemented:

### Internal Auth Location

```nginx
location = /_auth_verify {
    internal;
    proxy_pass http://127.0.0.1:3000/auth/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    # Send original context to backend
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;

    # Forward Authorization header
    proxy_set_header Authorization $http_authorization;
}
```

### Protected API Proxy

```nginx
location / {
    auth_request /_auth_verify;

    # Extract info from auth response
    auth_request_set $target_url $upstream_http_x_target_url;
    auth_request_set $user_id $upstream_http_x_user_id;
    # ...other user headers...

    # Dynamic Proxying (Resolver required for variables)
    resolver 8.8.8.8;
    proxy_pass $target_url$request_uri;

    # Inject context
    proxy_set_header X-User-Id $user_id;
    # ...other user headers...
}
```

## 4. Troubleshooting

- **Check Nginx logs**: `/var/log/nginx/api_gateway_error.log`
- **Resolver Error**: If using hostnames in the `permissions` table, Ensure a `resolver` is defined in the `http` or `server` block.
- **Port Conflict**: Ensure Nginx is not trying to bind to a port already used by the Auth Service or other microservices.
