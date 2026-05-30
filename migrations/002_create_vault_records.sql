CREATE TABLE IF NOT EXISTS vault_records (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token       VARCHAR(100) UNIQUE NOT NULL,
    field_type  VARCHAR(50) NOT NULL,
    enc_value   TEXT NOT NULL,
    nonce       VARCHAR(100) NOT NULL,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ
);
