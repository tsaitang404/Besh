import { handleJobAdmin } from './mcp-job-admin.ts'
import type { JobEnv } from '../domain/mcp-jobs.ts'
import { MCP_TOOLS, audit } from '../domain/mcp-store.ts'
import { jsonError } from './auth.ts'

/** Called only after the normal human administrator session and origin checks. */
export async function handleMcpAdmin(request: Request, env: JobEnv, path: string): Promise<Response> {
  if(path.startsWith('/api/mcp/jobs'))return handleJobAdmin(request,env,path)
  if (path === '/api/mcp/audit' && request.method === 'GET') {
    const rows = await env.DB.prepare('SELECT * FROM mcp_audit ORDER BY created_at DESC LIMIT 100').all()
    return Response.json({ events: rows.results }, { headers: { 'Cache-Control': 'no-store' } })
  }
  const match = /^\/api\/mcp\/agents(?:\/([A-Za-z0-9_-]{1,128}))?$/.exec(path)
  if (!match) return jsonError('NOT_FOUND', 'Unknown endpoint', 404)
  const id = match[1]
  if (request.method === 'GET' && !id) {
    const [agents, grants] = await Promise.all([env.DB.prepare('SELECT * FROM mcp_agents ORDER BY created_at').all(), env.DB.prepare('SELECT * FROM mcp_grants').all()])
    return Response.json({ agents: agents.results, grants: grants.results }, { headers: { 'Cache-Control': 'no-store' } })
  }
  if (request.method !== 'POST' && request.method !== 'PUT') return jsonError('INVALID_REQUEST', 'Method not allowed', 405)
  if (request.method === 'POST' && id || request.method === 'PUT' && !id) return jsonError('INVALID_REQUEST', 'Invalid operation', 400)
  let input: Record<string, unknown>
  try {
    const text = await request.text(); if (text.length > 16384) throw new Error()
    input = JSON.parse(text)
    if (!input || Array.isArray(input)) throw new Error()
  } catch { return jsonError('INVALID_REQUEST', 'Expected a small JSON object', 400) }
  const { name, commonName, enabled, expiresAt, grants, version } = input
  if (typeof name !== 'string' || !name.trim() || name.length > 100 || typeof commonName !== 'string' || !/^[a-zA-Z0-9_-]{1,128}\.access$/.test(commonName) || typeof enabled !== 'boolean' || typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now()+366*86400000 || !Array.isArray(grants) || grants.length > 300) return jsonError('INVALID_REQUEST', 'Invalid agent configuration', 400)
  const agentId = id ?? crypto.randomUUID(), now = Date.now(), nonce = crypto.randomUUID()
  if (id) {
    const current = await env.DB.prepare('SELECT version FROM mcp_agents WHERE id=?').bind(id).first<{version:number}>()
    if (!current) return jsonError('NOT_FOUND', 'Agent not found', 404)
    if (version !== current.version) return jsonError('INVALID_REQUEST', 'Agent changed; reload before saving', 409)
  }
  const unique = new Set<string>()
  for (const g of grants) {
    if (!g || typeof g.serverId !== 'string' || !(MCP_TOOLS as readonly unknown[]).includes(g.tool) || unique.has(`${g.serverId}:${g.tool}`)) return jsonError('INVALID_REQUEST', 'Invalid or duplicate grant', 400)
    unique.add(`${g.serverId}:${g.tool}`)
    if (!await env.DB.prepare('SELECT id FROM servers WHERE id=?').bind(g.serverId).first()) return jsonError('INVALID_REQUEST', 'Unknown server', 400)
  }
  const collision = await env.DB.prepare('SELECT id FROM mcp_agents WHERE access_common_name=? AND id<>?').bind(commonName, agentId).first()
  if (collision) return jsonError('INVALID_REQUEST', 'Machine identity already bound', 409)
  const statements: D1PreparedStatement[] = []
  if (id) {
    statements.push(env.DB.prepare('UPDATE mcp_agents SET name=?,access_common_name=?,enabled=?,expires_at=?,version=version+1,updated_at=?,config_nonce=? WHERE id=? AND version=?').bind(name.trim(), commonName, enabled?1:0, expiresAt, now, nonce, id, version))
    // Version check is repeated in each statement so stale concurrent updates cannot replace grants.
    statements.push(env.DB.prepare('DELETE FROM mcp_grants WHERE agent_id=? AND EXISTS(SELECT 1 FROM mcp_agents WHERE id=? AND config_nonce=?)').bind(id,id,nonce))
  } else statements.push(env.DB.prepare('INSERT INTO mcp_agents(id,name,access_common_name,enabled,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').bind(agentId,name.trim(),commonName,enabled?1:0,expiresAt,now,now))
  for (const g of grants) statements.push(env.DB.prepare('INSERT INTO mcp_grants(agent_id,server_id,tool) SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM mcp_agents WHERE id=? AND config_nonce=?)').bind(agentId,g.serverId,g.tool,agentId,id?nonce:''))
  const results = await env.DB.batch(statements)
  if (!results[0].meta.changes) return jsonError('INVALID_REQUEST', 'Concurrent agent update', 409)
  await audit(env.DB,{agentId,tool:'agent_configuration',outcome:enabled?'enabled':'disabled',started:now})
  return Response.json({ id: agentId, version: id?Number(version)+1:1 }, { status: id?200:201 })
}
