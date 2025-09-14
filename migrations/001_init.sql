-- Users: minimal record (we’ll extend later with auth logic)
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,             -- uuid string
  email         TEXT NOT NULL UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0,  -- 0 / 1
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Sessions: server-side session storage
CREATE TABLE IF NOT EXISTS sessions (
  id             TEXT PRIMARY KEY,            -- random session id
  user_id        TEXT NOT NULL,
  created_at     INTEGER NOT NULL DEFAULT (unixepoch()),
  idle_expires   INTEGER NOT NULL,            -- epoch seconds for idle timeout
  active_expires INTEGER NOT NULL,            -- epoch seconds for absolute max age
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Countdowns: per-user data
CREATE TABLE IF NOT EXISTS countdowns (
  id            TEXT PRIMARY KEY,             -- uuid string
  user_id       TEXT NOT NULL,
  name          TEXT NOT NULL CHECK (length(name) <= 200),
  stamp         TEXT NOT NULL,                -- RFC3339 timestamp (string)
  date_only     INTEGER NOT NULL DEFAULT 0,   -- 0 / 1
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_countdowns_user_time
  ON countdowns(user_id, stamp);

-- Triggers to keep updated_at fresh
CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
AFTER UPDATE ON users
FOR EACH ROW BEGIN
  UPDATE users SET updated_at = unixepoch() WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_countdowns_updated_at
AFTER UPDATE ON countdowns
FOR EACH ROW BEGIN
  UPDATE countdowns SET updated_at = unixepoch() WHERE id = NEW.id;
END;
