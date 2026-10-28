CREATE TABLE mcp_grants_background (
 agent_id TEXT NOT NULL REFERENCES mcp_agents(id) ON DELETE CASCADE,
 server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 tool TEXT NOT NULL CHECK(tool IN ('servers_list','server_status','diagnostic_run','command_exec','command_start','command_poll','command_cancel')),
 PRIMARY KEY(agent_id,server_id,tool)
);
INSERT INTO mcp_grants_background SELECT * FROM mcp_grants;
INSERT INTO mcp_grants_background SELECT agent_id,server_id,'command_start' FROM mcp_grants WHERE tool='command_exec';
INSERT INTO mcp_grants_background SELECT agent_id,server_id,'command_poll' FROM mcp_grants WHERE tool='command_exec';
INSERT INTO mcp_grants_background SELECT agent_id,server_id,'command_cancel' FROM mcp_grants WHERE tool='command_exec';
DROP TABLE mcp_grants;
ALTER TABLE mcp_grants_background RENAME TO mcp_grants;
CREATE TABLE mcp_background_tasks (
 id TEXT PRIMARY KEY,
 agent_id TEXT NOT NULL REFERENCES mcp_agents(id),
 server_id TEXT NOT NULL REFERENCES servers(id),
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 command_hash TEXT NOT NULL
);
CREATE INDEX mcp_background_owner ON mcp_background_tasks(agent_id,server_id);
