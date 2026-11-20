CREATE TABLE oauth_records (key TEXT PRIMARY KEY NOT NULL, payload TEXT NOT NULL, expires_at INTEGER);
--> statement-breakpoint
CREATE INDEX oauth_expiry ON oauth_records(expires_at);
--> statement-breakpoint
CREATE TABLE oauth_generations (user_id TEXT PRIMARY KEY NOT NULL, generation INTEGER NOT NULL DEFAULT 0);
