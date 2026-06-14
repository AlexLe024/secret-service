ALTER TABLE secrets ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'production'
    CHECK (environment IN ('development', 'staging', 'production'));
