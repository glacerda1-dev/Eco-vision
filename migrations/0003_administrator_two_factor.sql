ALTER TABLE users ADD COLUMN two_factor_secret_encrypted TEXT;
ALTER TABLE users ADD COLUMN two_factor_pending_secret_encrypted TEXT;
ALTER TABLE users ADD COLUMN two_factor_enabled_at TEXT;

CREATE TABLE admin_recovery_codes (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_admin_recovery_codes_user_unused
    ON admin_recovery_codes(user_id, used_at);
