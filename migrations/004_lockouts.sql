-- Track temporary lockouts by email
CREATE TABLE IF NOT EXISTS login_lockouts (
  email TEXT PRIMARY KEY,        -- normalized (lowercased)
  until INTEGER NOT NULL         -- epoch seconds when lockout expires
);
