-- Inferred from src/index.js
DROP TABLE IF EXISTS login_lockouts;
DROP TABLE IF EXISTS rl_attempts;
DROP TABLE IF EXISTS shares_pages;
DROP TABLE IF EXISTS countdowns;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_algo TEXT NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch())
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  idle_expires INTEGER NOT NULL,
  active_expires INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE countdowns (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  stamp TEXT NOT NULL,
  date_only INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE shares_pages (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()),
  expires_at INTEGER,
  revoked_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE rl_attempts (
  key TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX idx_rl_attempts_key_ts ON rl_attempts (key, ts);
CREATE TABLE login_lockouts (
  email TEXT PRIMARY KEY,
  until INTEGER NOT NULL
);
