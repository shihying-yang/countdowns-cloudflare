-- Track auth attempts for rate limiting (small & simple)
CREATE TABLE IF NOT EXISTS rl_attempts (
  key        TEXT NOT NULL,                -- e.g., "login:ip:1.2.3.4" or "login:email:foo@bar"
  ts         INTEGER NOT NULL              -- epoch seconds
);

CREATE INDEX IF NOT EXISTS idx_rl_key_ts ON rl_attempts(key, ts);
