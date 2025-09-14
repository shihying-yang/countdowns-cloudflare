-- 005_shares.sql
-- Read-only share tokens for countdowns (table + indexes only)

CREATE TABLE IF NOT EXISTS shares (
  token         TEXT PRIMARY KEY,             -- UUIDv4
  user_id       TEXT NOT NULL,                -- owner
  countdown_id  TEXT NOT NULL,                -- which countdown is shared
  created_at    INTEGER NOT NULL DEFAULT unixepoch(),
  revoked_at    INTEGER,                      -- null = active
  expires_at    INTEGER,                      -- null = no expiry

  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (countdown_id) REFERENCES countdowns(id)
);

CREATE INDEX IF NOT EXISTS idx_shares_user       ON shares(user_id);
CREATE INDEX IF NOT EXISTS idx_shares_countdown  ON shares(countdown_id);
