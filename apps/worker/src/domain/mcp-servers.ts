import { readCredentialKey } from './credential-key.ts'
import { sealCredential } from './credentials.ts'
import { getServerPublic } from './server-store.ts'
import { resolvePublicTarget } from './target.ts'
import { MCP_TOOLS, type MachineAgent } from './mcp-store.ts'

export const SERVER_CREATE_PROPERTIES = {
  requestId: { type: 'string', format: 'uuid', description: 'Generate once per host creation. Reuse the same ID after a lost response; retries return the existing host without updating credentials.' },
  name: { type: 'string', minLength: 1, maxLength: 120 },
  host: { type: 'string', minLength: 1, maxLength: 253 },
  port: { type: 'integer', minimum: 1, maximum: 65535, default: 22 },
  username: { type: 'string', minLength: 1, maxLength: 128 },
  authMethod: { type: 'string', enum: ['password','publickey'] },
  credential: { type: 'string', minLength: 1, maxLength: 8192, description: 'SSH password or private key. Encrypted at rest; never echoed or written to the audit log. Supply through an authorized credential source.' },
  fingerprint: { type: 'string', pattern: '^SHA256:[A-Za-z0-9+/]{43}=?$', description: 'Expected SHA256 SSH host-key fingerprint obtained from a trusted source. Future connections must match it. Creating an inventory record does not verify reachability or login.' },
}
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
export function validServerCreate(a: Record<string, unknown>): boolean {
  return typeof a.requestId==='string' && UUID.test(a.requestId)
    && typeof a.name==='string' && a.name.trim().length>0 && a.name.length<=120
    && typeof a.host==='string' && a.host.trim().length>0 && a.host.length<=253
    && (a.port===undefined || (Number.isInteger(a.port) && Number(a.port)>=1 && Number(a.port)<=65535))
    && typeof a.username==='string' && a.username.trim().length>0 && a.username.length<=128 && !/[\0\r\n]/.test(a.username)
    && ['password','publickey'].includes(String(a.authMethod))
    && typeof a.credential==='string' && a.credential.length>0 && new TextEncoder().encode(a.credential).length<=8192
    && typeof a.fingerprint==='string' && /^SHA256:[A-Za-z0-9+/]{43}=?$/.test(a.fingerprint)
}
export async function checkCreateGrant(db: D1Database, agent: MachineAgent): Promise<void> {
  const live = await db.prepare('SELECT id FROM mcp_agents WHERE id=? AND enabled=1 AND expires_at>? AND version=? AND can_create_servers=1').bind(agent.id,Date.now(),agent.version).first()
  if (!live) throw new Error('ACCESS_DENIED')
}
export async function createMcpServer(env: { DB: D1Database; CREDENTIAL_KEY: string; CREDENTIAL_KEY_VERSION?: string }, agent: MachineAgent, args: Record<string, unknown>) {
  await checkCreateGrant(env.DB, agent)
  const id=String(args.requestId), now=Date.now()
  const owned=await env.DB.prepare('SELECT server_id FROM mcp_created_servers WHERE server_id=? AND agent_id=?').bind(id,agent.id).first()
  if (owned) return {server: await getServerPublic(env.DB,id), created:false, connectionVerified:false}
  const host=String(args.host).trim()
  await resolvePublicTarget(host,{resolve:async hostname=>{
    const url=new URL('https://cloudflare-dns.com/dns-query');url.searchParams.set('name',hostname);url.searchParams.set('type','A')
    const response=await fetch(url,{headers:{Accept:'application/dns-json'},signal:AbortSignal.timeout(5000)})
    if(!response.ok)throw new Error('DNS_UNAVAILABLE')
    const data=await response.json() as {Answer?:Array<{type:number;data:string}>}
    return (data.Answer??[]).filter(a=>a.type===1||a.type===28).map(a=>a.data)
  }})
  const key=readCredentialKey(env);if(!key)throw new Error('CREDENTIAL_UNAVAILABLE')
  const rawVersion=Number(env.CREDENTIAL_KEY_VERSION??1), keyVersion=Number.isInteger(rawVersion)&&rawVersion>0?rawVersion:1
  const credential=await sealCredential(key,String(args.credential),{serverId:id,kind:args.authMethod==='publickey'?'privateKey':'password',keyVersion})
  // One atomic batch: inventory, ownership and all host tools. Recheck permission in the write itself.
  const statements=[env.DB.prepare(`INSERT INTO servers(id,name,host,port,username,auth_method,group_id,credential,fingerprint,trusted_at,version,created_at,updated_at)
    SELECT ?,?,?,?,?,?,NULL,?,?,?,1,?,? WHERE EXISTS(SELECT 1 FROM mcp_agents WHERE id=? AND enabled=1 AND expires_at>? AND version=? AND can_create_servers=1)`)
    .bind(id,String(args.name).trim(),host,Number(args.port??22),String(args.username).trim(),args.authMethod,JSON.stringify(credential),args.fingerprint,now,now,now,agent.id,now,agent.version),
    env.DB.prepare('INSERT INTO mcp_created_servers(server_id,agent_id) SELECT id,? FROM servers WHERE id=? AND created_at=? AND EXISTS(SELECT 1 FROM mcp_agents WHERE id=? AND enabled=1 AND expires_at>? AND version=? AND can_create_servers=1)').bind(agent.id,id,now,agent.id,now,agent.version)]
  for(const tool of MCP_TOOLS.filter(t=>t!=='server_create'))statements.push(env.DB.prepare('INSERT INTO mcp_grants(agent_id,server_id,tool) SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM mcp_created_servers WHERE server_id=? AND agent_id=?)').bind(agent.id,id,tool,id,agent.id))
  try {
    const results=await env.DB.batch(statements)
    if(!results[0].meta.changes)throw new Error('ACCESS_DENIED')
  } catch(e) {
    // A simultaneous retry can have committed the same request ID first.
    if(await env.DB.prepare('SELECT server_id FROM mcp_created_servers WHERE server_id=? AND agent_id=?').bind(id,agent.id).first())return {server:await getServerPublic(env.DB,id),created:false,connectionVerified:false}
    throw e
  }
  return {server:await getServerPublic(env.DB,id),created:true,connectionVerified:false}
}

export const SERVER_UPDATE_PROPERTIES = {
  ...Object.fromEntries(Object.entries(SERVER_CREATE_PROPERTIES).filter(([k])=>k!=='requestId')),
  serverId: {type:'string',minLength:1,maxLength:128},
  version: {type:'integer',minimum:1,description:'Current version from servers_list. A stale version fails without changing anything.'},
}
export function validServerUpdate(args: Record<string,unknown>): boolean {
  return Number.isSafeInteger(args.version) && Number(args.version)>0
    && (args.credential===undefined || (typeof args.credential==='string' && args.credential.length>0))
    && validServerCreate({...args,requestId:'00000000-0000-4000-8000-000000000000',credential:args.credential??'unchanged'})
}
export async function updateMcpServer(env: {DB:D1Database;CREDENTIAL_KEY:string;CREDENTIAL_KEY_VERSION?:string}, agent:MachineAgent, args:Record<string,unknown>) {
  const {checkGrant}=await import('./mcp-store.ts')
  const id=String(args.serverId)
  await checkGrant(env.DB,agent,id,'server_update')
  const existing=await getServerPublic(env.DB,id)
  if(!existing)throw new Error('SERVER_NOT_FOUND')
  if(existing.version!==args.version)throw new Error('VERSION_CONFLICT')
  if(existing.authMethod!==args.authMethod && args.credential===undefined)throw new Error('CREDENTIAL_REQUIRED')
  const host=String(args.host).trim()
  await resolvePublicTarget(host,{resolve:async hostname=>{
    const url=new URL('https://cloudflare-dns.com/dns-query');url.searchParams.set('name',hostname);url.searchParams.set('type','A')
    const r=await fetch(url,{headers:{Accept:'application/dns-json'},signal:AbortSignal.timeout(5000)})
    if(!r.ok)throw new Error('DNS_UNAVAILABLE')
    const data=await r.json() as {Answer?:Array<{type:number;data:string}>}
    return (data.Answer??[]).filter(a=>a.type===1||a.type===28).map(a=>a.data)
  }})
  let sealed:string|null=null
  if(args.credential!==undefined){
    const key=readCredentialKey(env);if(!key)throw new Error('CREDENTIAL_UNAVAILABLE')
    const v=Number(env.CREDENTIAL_KEY_VERSION??1)
    sealed=JSON.stringify(await sealCredential(key,String(args.credential),{serverId:id,kind:args.authMethod==='publickey'?'privateKey':'password',keyVersion:Number.isInteger(v)&&v>0?v:1}))
  }
  const now=Date.now()
  const result=await env.DB.prepare(`UPDATE servers SET name=?,host=?,port=?,username=?,auth_method=?,credential=COALESCE(?,credential),fingerprint=?,trusted_at=?,os=CASE WHEN host<>? OR port<>? THEN NULL ELSE os END,version=version+1,updated_at=?
   WHERE id=? AND version=? AND EXISTS(SELECT 1 FROM mcp_agents a JOIN mcp_grants g ON a.id=g.agent_id WHERE a.id=? AND a.enabled=1 AND a.expires_at>? AND a.version=? AND g.server_id=? AND g.tool='server_update')`)
   .bind(String(args.name).trim(),host,Number(args.port??22),String(args.username).trim(),args.authMethod,sealed,args.fingerprint,now,host,Number(args.port??22),now,id,args.version,agent.id,now,agent.version,id).run()
  if(!result.meta.changes){await checkGrant(env.DB,agent,id,'server_update');throw new Error('VERSION_CONFLICT')}
  return {server:await getServerPublic(env.DB,id),updated:true,connectionVerified:false}
}
export async function deleteMcpServer(env: {DB:D1Database;ATTACHMENTS?:import('./attachments.ts').AttachmentBucket}, agent:MachineAgent, args:Record<string,unknown>) {
  const {checkGrant}=await import('./mcp-store.ts')
  const id=String(args.serverId)
  await checkGrant(env.DB,agent,id,'server_delete')
  const existing=await getServerPublic(env.DB,id)
  if(!existing)throw new Error('SERVER_NOT_FOUND')
  if(existing.version!==args.version)throw new Error('VERSION_CONFLICT')
  const result=await env.DB.prepare(`DELETE FROM servers WHERE id=? AND version=? AND EXISTS(SELECT 1 FROM mcp_agents a JOIN mcp_grants g ON a.id=g.agent_id WHERE a.id=? AND a.enabled=1 AND a.expires_at>? AND a.version=? AND g.server_id=? AND g.tool='server_delete')`)
   .bind(id,args.version,agent.id,Date.now(),agent.version,id).run()
  if(!result.meta.changes){await checkGrant(env.DB,agent,id,'server_delete');throw new Error('VERSION_CONFLICT')}
  // Keep audit records; remove inaccessible host history. Report cleanup separately from deletion.
  let historyCleaned=false
  try {
    if(env.ATTACHMENTS){const {forgetServerHistory}=await import('./ai-history.ts');await forgetServerHistory(env.DB,env.ATTACHMENTS,id)}
    else {await env.DB.batch(['ai_messages','ai_conversations','ai_usage'].map(table=>env.DB.prepare(`DELETE FROM ${table} WHERE server_id=?`).bind(id)))}
    await env.DB.prepare('DELETE FROM mcp_jobs WHERE server_id=?').bind(id).run()
    historyCleaned=true
  } catch { /* Host removal succeeded; do not invite a duplicate destructive retry. */ }
  return {serverId:id,deleted:true,historyCleaned,remoteProcessesStopped:false}
}
