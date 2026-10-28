export const MCP_TOOLS = ['servers_list', 'server_status', 'diagnostic_run', 'command_exec', 'command_start', 'command_poll', 'command_cancel', 'server_create', 'server_update', 'server_delete'] as const
export type McpTool = typeof MCP_TOOLS[number]
export type MachineAgent = { id: string; name: string; access_common_name: string; enabled: number; expires_at: number; version: number; can_create_servers: number }
export async function findAgent(db: D1Database, commonName: string): Promise<MachineAgent | null> {
  return db.prepare('SELECT id,name,access_common_name,enabled,expires_at,version,can_create_servers FROM mcp_agents WHERE access_common_name=? AND enabled=1 AND expires_at>?').bind(commonName, Date.now()).first<MachineAgent>()
}
export async function checkGrant(db: D1Database, agent: MachineAgent, serverId: string, tool: string): Promise<void> {
  const row = await db.prepare('SELECT a.id FROM mcp_agents a JOIN mcp_grants g ON a.id=g.agent_id WHERE a.id=? AND a.enabled=1 AND a.expires_at>? AND a.version=? AND g.server_id=? AND g.tool=?')
    .bind(agent.id, Date.now(), agent.version, serverId, tool).first()
  if (!row) throw new Error('ACCESS_DENIED')
}
export async function audit(db: D1Database, input: { agentId: string | null; tool: string; serverId?: string; diagnostic?: string; outcome: string; started: number; commandHash?: string }): Promise<void> {
  await db.prepare('INSERT INTO mcp_audit(id,agent_id,tool,server_id,diagnostic,outcome,created_at,duration_ms,command_hash) VALUES(?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(), input.agentId, input.tool, input.serverId ?? null, input.diagnostic ?? null, input.outcome, Date.now(), Date.now()-input.started,input.commandHash??null).run()
}
