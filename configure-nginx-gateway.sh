#!/bin/bash

# Exit on error
set -e

echo "Starting Nginx API Gateway configuration..."

# 1. Install Nginx if not present
if ! command -v nginx &> /dev/null; then
    echo "Nginx not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y nginx
else
    echo "Nginx is already installed."
fi

# 2. Create necessary directory structure
echo "Creating Nginx configuration structure..."
sudo mkdir -p /etc/nginx/sites-available
sudo mkdir -p /etc/nginx/sites-enabled

# 3. Generate Nginx configuration file
NGINX_CONF="/etc/nginx/sites-available/api-gateway"
AUTH_SERVICE_URL="http://127.0.0.1:3000"

echo "Generating Nginx configuration at $NGINX_CONF..."

cat <<EOF | sudo tee $NGINX_CONF
server {
    listen 80;
    server_name localhost;

    # resolver is required when using variables in proxy_pass
    resolver 8.8.8.8 1.1.1.1 valid=300s;
    resolver_timeout 5s;

    # Logging
    access_log /var/log/nginx/api_gateway_access.log;
    error_log /var/log/nginx/api_gateway_error.log;

    # 1. Internal Authentication & Authorization subrequest
    location = /_auth_verify {
        internal;
        proxy_pass $AUTH_SERVICE_URL/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        # Pass original request context to the auth service
        proxy_set_header X-Original-URI \$request_uri;
        proxy_set_header X-Original-Method \$request_method;

        # Forward Authorization header if present
        proxy_set_header Authorization \$http_authorization;
    }

    # 2. Authentication endpoints (Public)
    location /auth/ {
        proxy_pass $AUTH_SERVICE_URL;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    # 3. Protected API Routes
    location / {
        # Perform authentication subrequest
        auth_request /_auth_verify;

        # Extract context from auth service response headers
        auth_request_set \$target_url \$upstream_http_x_target_url;
        auth_request_set \$user_id \$upstream_http_x_user_id;
        auth_request_set \$user_email \$upstream_http_x_user_email;
        auth_request_set \$user_role \$upstream_http_x_user_role;
        auth_request_set \$user_dept \$upstream_http_x_user_department_id;

        # Proxy to the dynamic target URL returned by the gateway.
        # We append \$request_uri to maintain the path.
        proxy_pass \$target_url\$request_uri;

        # Inject validated user context for the microservice
        proxy_set_header X-User-Id \$user_id;
        proxy_set_header X-User-Email \$user_email;
        proxy_set_header X-User-Role \$user_role;
        proxy_set_header X-User-Department-Id \$user_dept;

        # Standard headers
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

        # Error handling for unauthorized or forbidden
        error_page 401 = @unauthorized;
        error_page 403 = @forbidden;
    }

    location @unauthorized {
        add_header Content-Type application/json always;
        return 401 '{"success": false, "message": "Unauthorized: Authentication required"}';
    }

    location @forbidden {
        add_header Content-Type application/json always;
        return 403 '{"success": false, "message": "Forbidden: Insufficient permissions"}';
    }
}
EOF

# 4. Enable the configuration
echo "Enabling the configuration..."
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi

sudo ln -sf $NGINX_CONF /etc/nginx/sites-enabled/api-gateway

# 5. Test and Restart Nginx
echo "Testing Nginx configuration..."
sudo nginx -t

echo "Restarting Nginx service..."
sudo systemctl restart nginx

echo "Nginx API Gateway configured successfully!"
