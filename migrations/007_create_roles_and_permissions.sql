CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);

CREATE TABLE IF NOT EXISTS role_permissions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id      UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    field_type   VARCHAR(50) NOT NULL,
    access_level VARCHAR(20) NOT NULL CHECK (access_level IN ('FULL', 'MASKED', 'DENIED')),
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(role_id, field_type)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
