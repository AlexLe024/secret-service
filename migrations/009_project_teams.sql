-- Records which teams have been assigned to which projects.
-- Assigning a team bulk-adds all its current members to project_members.
CREATE TABLE IF NOT EXISTS project_teams (
    project_id  TEXT        NOT NULL REFERENCES projects(id)  ON DELETE CASCADE,
    team_id     TEXT        NOT NULL REFERENCES teams(id)     ON DELETE CASCADE,
    assigned_by TEXT        NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, team_id)
);
