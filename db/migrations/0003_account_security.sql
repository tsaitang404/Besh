ALTER TABLE admin ADD COLUMN security_version INTEGER NOT NULL DEFAULT 0 CHECK (security_version >= 0);
CREATE TABLE account_security (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 totp TEXT,
 last_step INTEGER NOT NULL DEFAULT -1
);
INSERT INTO account_security(id) VALUES (1);
CREATE TABLE passkeys (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 public_key TEXT NOT NULL,
 counter INTEGER NOT NULL,
 transports TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE auth_challenges (
 id TEXT PRIMARY KEY,
 purpose TEXT NOT NULL,
 payload TEXT NOT NULL,
 session_hash TEXT NOT NULL,
 version INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE TABLE recovery_codes (hash TEXT PRIMARY KEY);
CREATE TABLE auth_limits (bucket TEXT PRIMARY KEY, attempts INTEGER NOT NULL);
