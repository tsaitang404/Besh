-- Machine identities are independent of human sessions. No bearer secrets stored here.
CREATE TABLE mcp_agents (
 id TEXT PRIMARY KEY, name TEXT NOT NULL,
 access_common_name TEXT NOT NULL UNIQUE,
 enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
 expires_at INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 1,
 config_nonce TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE mcp_grants (
 agent_id TEXT NOT NULL REFERENCES mcp_agents(id) ON DELETE CASCADE,
 server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 tool TEXT NOT NULL CHECK(tool IN ('servers_list','server_status','diagnostic_run')),
 PRIMARY KEY(agent_id,server_id,tool)
);
CREATE TABLE mcp_audit (
 id TEXT PRIMARY KEY, agent_id TEXT, tool TEXT NOT NULL, server_id TEXT,
 diagnostic TEXT, outcome TEXT NOT NULL, created_at INTEGER NOT NULL, duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX mcp_audit_time ON mcp_audit(created_at);
CREATE TABLE mcp_leases (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX mcp_leases_expiry ON mcp_leases(expires_at);
