-- Create departments table
CREATE TABLE IF NOT EXISTS departments (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    role_id INTEGER REFERENCES roles(id),
    department_id INTEGER REFERENCES departments(id),
    two_factor_secret VARCHAR(255),
    is_two_factor_enabled BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create permissions table (including gateway config)
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    route_path VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    target_url VARCHAR(255), -- NULL if handled by the auth service itself
    is_owner_resource BOOLEAN DEFAULT FALSE,
    is_public BOOLEAN DEFAULT FALSE,
    department_id INTEGER REFERENCES departments(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(route_path, method)
);

-- Create role_permissions junction table
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Create providers table for OAuth
CREATE TABLE IF NOT EXISTS providers (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    provider_name VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider_name, provider_user_id)
);

-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(512) NOT NULL UNIQUE,
    jti VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100),
    method VARCHAR(10),
    path TEXT,
    status_code INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    payload JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Initial Data
INSERT INTO roles (name) VALUES ('admin'), ('user'), ('manager');

INSERT INTO departments (name) VALUES ('IT'), ('Sales'), ('HR');

-- Admin user (password: admin123)
-- Hash for 'admin123': $2a$10$X86Z/BfP5.b.9Vf2W5m.Ou9nLzQ4uQ.I3h3G9Vf2W5m.Ou9nLzQ4uQ
INSERT INTO users (email, password, name, role_id, department_id)
VALUES ('admin@example.com', '$2a$10$X86Z/BfP5.b.9Vf2W5m.Ou9nLzQ4uQ.I3h3G9Vf2W5m.Ou9nLzQ4uQ', 'Admin User', 1, 1);

-- Sample permissions
INSERT INTO permissions (name, description, route_path, method, target_url, is_owner_resource, is_public)
VALUES
('login', 'User login', '/auth/login', 'POST', NULL, FALSE, TRUE),
('register', 'User registration', '/auth/register', 'POST', NULL, FALSE, TRUE),
('get_profile', 'Get own profile', '/auth/profile', 'GET', NULL, TRUE, FALSE),
('view_products', 'View all products', '/api/products', 'GET', 'http://localhost:3001', FALSE, FALSE),
('create_product', 'Create a new product', '/api/products', 'POST', 'http://localhost:3001', FALSE, FALSE);

-- Assign all permissions to admin
INSERT INTO role_permissions (role_id, permission_id)
SELECT 1, id FROM permissions;

-- Assign some permissions to user
INSERT INTO role_permissions (role_id, permission_id)
SELECT 2, id FROM permissions WHERE name IN ('get_profile', 'view_products');
