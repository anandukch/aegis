-- Seed the four built-in system roles. is_system=true prevents deletion via API.
-- field_type='*' is the default/fallback permission when no exact field match exists.

INSERT INTO roles (name, description, is_system) VALUES
    ('ADMIN',   'Full access to all fields and admin operations', TRUE),
    ('ANALYST', 'Masked access to most fields; denied access to card numbers', TRUE),
    ('SERVICE', 'Full access to card numbers; masked access to all other fields', TRUE),
    ('VIEWER',  'Masked access to all fields', TRUE)
ON CONFLICT (name) DO NOTHING;

-- ADMIN: full access to everything (default '*' covers all fields)
INSERT INTO role_permissions (role_id, field_type, access_level)
SELECT id, '*', 'FULL' FROM roles WHERE name = 'ADMIN'
ON CONFLICT (role_id, field_type) DO NOTHING;

-- ANALYST: masked default, masked for specific fields, denied for card_number
INSERT INTO role_permissions (role_id, field_type, access_level)
SELECT id, '*',           'MASKED' FROM roles WHERE name = 'ANALYST'
ON CONFLICT (role_id, field_type) DO NOTHING;

INSERT INTO role_permissions (role_id, field_type, access_level)
SELECT id, 'email',       'MASKED' FROM roles WHERE name = 'ANALYST'
ON CONFLICT (role_id, field_type) DO NOTHING;

INSERT INTO role_permissions (role_id, field_type, access_level)
SELECT id, 'name',        'MASKED' FROM roles WHERE name = 'ANALYST'
ON CONFLICT (role_id, field_type) DO NOTHING;

INSERT INTO role_permissions (role_id, field_type, access_level)
SELECT id, 'card_number', 'DENIED' FROM roles WHERE name = 'ANALYST'
ON CONFLICT (role_id, field_type) DO NOTHING;

-- SERVICE: full for card_number, masked for everything else
INSERT INTO role_permissions (role_id, field_type, access_level)
SELECT id, '*',           'MASKED' FROM roles WHERE name = 'SERVICE'
ON CONFLICT (role_id, field_type) DO NOTHING;

INSERT INTO role_permissions (role_id, field_type, access_level)
SELECT id, 'card_number', 'FULL'   FROM roles WHERE name = 'SERVICE'
ON CONFLICT (role_id, field_type) DO NOTHING;

-- VIEWER: masked access to all fields
INSERT INTO role_permissions (role_id, field_type, access_level)
SELECT id, '*', 'MASKED' FROM roles WHERE name = 'VIEWER'
ON CONFLICT (role_id, field_type) DO NOTHING;
