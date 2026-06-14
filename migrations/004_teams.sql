CREATE TABLE teams (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE team_members (
    id         TEXT PRIMARY KEY,
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (team_id, user_id)
);

ALTER TABLE projects ADD COLUMN IF NOT EXISTS team_id TEXT REFERENCES teams(id);
