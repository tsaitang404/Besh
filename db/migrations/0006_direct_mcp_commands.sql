CREATE TABLE mcp_grants_direct (
 agent_id TEXT NOT NULL REFERENCES mcp_agents(id) ON DELETE CASCADE,
 server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 tool TEXT NOT NULL CHECK(tool IN ('servers_list','server_status','diagnostic_run','command_exec')),
 PRIMARY KEY(agent_id,server_id,tool)
);
INSERT INTO mcp_grants_direct SELECT * FROM mcp_grants WHERE tool IN ('servers_list','server_status','diagnostic_run');
DROP TABLE mcp_grants;
ALTER TABLE mcp_grants_direct RENAME TO mcp_grants;
ALTER TABLE mcp_audit ADD COLUMN command_hash TEXT;
