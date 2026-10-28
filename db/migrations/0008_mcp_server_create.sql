ALTER TABLE mcp_agents ADD COLUMN can_create_servers INTEGER NOT NULL DEFAULT 0 CHECK(can_create_servers IN (0,1));
CREATE TABLE mcp_created_servers (
 server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
 agent_id TEXT NOT NULL REFERENCES mcp_agents(id)
);
-- The owner authorized full inventory management through the existing Portal identity.
UPDATE mcp_agents SET can_create_servers=1,version=version+1 WHERE id='besh-portal';
CREATE TABLE mcp_grants_inventory (
 agent_id TEXT NOT NULL REFERENCES mcp_agents(id) ON DELETE CASCADE,
 server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 tool TEXT NOT NULL CHECK(tool IN ('servers_list','server_status','diagnostic_run','command_exec','command_start','command_poll','command_cancel','server_update','server_delete')),
 PRIMARY KEY(agent_id,server_id,tool)
);
INSERT INTO mcp_grants_inventory SELECT * FROM mcp_grants;
INSERT INTO mcp_grants_inventory SELECT agent_id,server_id,'server_update' FROM mcp_grants WHERE tool='command_exec' AND agent_id='besh-portal';
INSERT INTO mcp_grants_inventory SELECT agent_id,server_id,'server_delete' FROM mcp_grants WHERE tool='command_exec' AND agent_id='besh-portal';
DROP TABLE mcp_grants;
ALTER TABLE mcp_grants_inventory RENAME TO mcp_grants;
-- Host deletion must also remove background task lookup metadata.
CREATE TABLE mcp_background_tasks_inventory (
 id TEXT PRIMARY KEY,
 agent_id TEXT NOT NULL REFERENCES mcp_agents(id),
 server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 command_hash TEXT NOT NULL
);
INSERT INTO mcp_background_tasks_inventory SELECT * FROM mcp_background_tasks;
DROP TABLE mcp_background_tasks;
ALTER TABLE mcp_background_tasks_inventory RENAME TO mcp_background_tasks;
CREATE INDEX mcp_background_owner ON mcp_background_tasks(agent_id,server_id);
