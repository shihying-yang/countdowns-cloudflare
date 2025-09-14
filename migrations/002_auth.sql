-- Add password-based auth fields to users
ALTER TABLE users ADD COLUMN password_hash TEXT;
ALTER TABLE users ADD COLUMN password_salt TEXT;
ALTER TABLE users ADD COLUMN password_algo TEXT DEFAULT 'pbkdf2-sha256';

-- Backfill any existing rows to non-null-ish values (so future NOT NULL is easy)
UPDATE users
SET
  password_hash = COALESCE(password_hash, ''),
  password_salt = COALESCE(password_salt, ''),
  password_algo = COALESCE(password_algo, 'pbkdf2-sha256');
