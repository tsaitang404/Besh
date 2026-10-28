-- Explicit grants; existing read-only principals acquire no execution grants implicitly.
CREATE TABLE mcp_grants_v2 (
 agent_id TEXT NOT NULL REFERENCES mcp_agents(id) ON DELETE CASCADE,
 server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 tool TEXT NOT NULL CHECK(tool IN ('servers_list','server_status','diagnostic_run','command_submit','command_start','command_status','command_cancel')),
 PRIMARY KEY(agent_id,server_id,tool)
);
INSERT INTO mcp_grants_v2 SELECT * FROM mcp_grants;
DROP TABLE mcp_grants;
ALTER TABLE mcp_grants_v2 RENAME TO mcp_grants;
CREATE TABLE mcp_exec_profiles (
 server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
 username TEXT NOT NULL CHECK(username <> 'root'),
 credential TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
 version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE mcp_jobs (
 id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, server_id TEXT NOT NULL,
 agent_version INTEGER NOT NULL, snapshot TEXT NOT NULL,
 command_sealed TEXT, command_hash TEXT NOT NULL,
 timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds BETWEEN 1 AND 120),
 max_output_bytes INTEGER NOT NULL CHECK(max_output_bytes BETWEEN 1024 AND 65536),
 status TEXT NOT NULL CHECK(status IN ('pending','approved','queued','running','succeeded','failed','cancelled','timed_out','revoked','interrupted','expired','rejected')),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 approved_at INTEGER, approval_expires_at INTEGER, approved_by TEXT, approval_security_version INTEGER,
 started_at INTEGER, finished_at INTEGER, cancel_requested INTEGER NOT NULL DEFAULT 0,
 result_sealed TEXT, outcome TEXT
);
CREATE INDEX mcp_jobs_owner ON mcp_jobs(agent_id,created_at);
CREATE INDEX mcp_jobs_status ON mcp_jobs(status,created_at);
ALTER TABLE mcp_audit ADD COLUMN job_id TEXT;
