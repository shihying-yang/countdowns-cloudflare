wrangler d1 execute countdowns_db --remote --command "CREATE TABLE IF NOT EXISTS shares_pages ( token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (unixepoch()), revoked_at INTEGER, expires_at INTEGER );"

wrangler d1 execute countdowns_db --remote --command "CREATE INDEX IF NOT EXISTS idx_shares_pages_user ON shares_pages(user_id);"

wrangler d1 execute countdowns_db --remote --command "SELECT name, type FROM sqlite_schema WHERE name IN ('shares_pages','idx_shares_pages_user');"
