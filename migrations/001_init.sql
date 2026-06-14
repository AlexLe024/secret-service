CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users
CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Projects
CREATE TABLE projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Project members (RBAC: admin / manager / developer)
CREATE TABLE project_members (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('admin', 'manager', 'developer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, user_id)
);

-- Secrets (metadata only, value stored encrypted in secret_versions)
CREATE TABLE secrets (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, name)
);

-- Secret versions (versioned encrypted values)
CREATE TABLE secret_versions (
    id              TEXT PRIMARY KEY,
    secret_id       TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version         INT  NOT NULL,
    encrypted_value BYTEA NOT NULL,
    nonce           BYTEA NOT NULL,
    is_current      BOOLEAN NOT NULL DEFAULT FALSE,
    created_by      TEXT NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id, version)
);

CREATE INDEX idx_secret_versions_current ON secret_versions (secret_id) WHERE is_current = TRUE;

-- Access grants (временный доступ к секрету для конкретного пользователя)
CREATE TABLE access_grants (
    id          TEXT PRIMARY KEY,
    secret_id   TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_by  TEXT NOT NULL REFERENCES users(id),
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id, user_id)
);

-- Audit log
CREATE TABLE audit_events (
    id            TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id),
    project_id    TEXT REFERENCES projects(id),
    secret_id     TEXT REFERENCES secrets(id),
    event_type    TEXT NOT NULL,
    metadata      JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_project ON audit_events (project_id, created_at DESC);
CREATE INDEX idx_audit_secret  ON audit_events (secret_id,  created_at DESC);
