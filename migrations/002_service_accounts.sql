CREATE TABLE service_accounts (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    token_hash  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, name)
);

CREATE INDEX idx_service_accounts_project ON service_accounts (project_id);
