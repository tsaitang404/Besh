import { getServerPublic } from './server-store.ts'
import { readCredentialKey } from './credential-key.ts'
import { openCredential, sealCredential, type SealedCredential } from './credentials.ts'
import { checkGrant, audit, type MachineAgent } from './mcp-store.ts'
import { getAdmin } from './admin-store.ts'
export type JobEnv = { DB: D1Database; CREDENTIAL_KEY: string; COMMAND_JOBS: DurableObjectNamespace; MCP_ENABLED?: string; MCP_EXEC_PROFILE_SEED?: string }
export type ExecProfile = { server_id: string; username: string; credential: string; enabled: number; version: number }
export type Job = {
 id: string; agent_id: string; server_id: string; agent_version: number; snapshot: string;
 command_sealed: string | null; command_hash: string; timeout_seconds: number; max_output_bytes: number;
 status: string; created_at: number; expires_at: number; approved_at: number | null; approval_expires_at: number | null;
 approved_by: string | null; approval_security_version: number | null; started_at: number | null; finished_at: number | null;
 cancel_requested: number; result_sealed: string | null; outcome: string | null;
}
export const TERMINAL = ['succeeded','failed','cancelled','timed_out','revoked','interrupted','expired','rejected']
export const SYSTEM_PATH = 'PATH=/run/current-system/sw/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH; '
export const shellQuote = (text: string) => "'" + text.replaceAll("'", "'\\''") + "'"
export function jobUnit(id: string): string {
 if (!/^[a-f0-9-]{36}$/.test(id)) throw new Error('INVALID_JOB')
 return `besh-${id}.service`
}
/** A dedicated account, cgroup kill and remote deadline survive Worker disconnects. */
export function jobCommand(job: Job, command: string): string {
 return SYSTEM_PATH + `exec systemd-run --user --quiet --wait --pipe --collect --unit=${jobUnit(job.id)} --property=KillMode=control-group --property=TimeoutStopSec=2s --property=RuntimeMaxSec=${job.timeout_seconds}s --property=NoNewPrivileges=yes --property=MemoryMax=256M --property=TasksMax=32 --property=CPUQuota=100% --setenv=PATH=/run/current-system/sw/bin:/usr/bin:/bin sh -c ${shellQuote(command)}`
}
export const getJob = (db: D1Database, id: string) => db.prepare('SELECT * FROM mcp_jobs WHERE id=?').bind(id).first<Job>()
export const getProfile = (db: D1Database, id: string) => db.prepare('SELECT * FROM mcp_exec_profiles WHERE server_id=?').bind(id).first<ExecProfile>()
export async function sealJob(env: JobEnv, id: string, value: string, kind: 'mcpCommand'|'mcpOutput'): Promise<string> {
 const key=readCredentialKey(env);if(!key)throw new Error('KEY_UNAVAILABLE')
 return JSON.stringify(await sealCredential(key,value,{serverId:id,kind,keyVersion:1}))
}
export async function openJob(env: JobEnv, id: string, value: string, kind: 'mcpCommand'|'mcpOutput'): Promise<string> {
 const key=readCredentialKey(env);if(!key)throw new Error('KEY_UNAVAILABLE')
 return openCredential(key,JSON.parse(value) as SealedCredential,{serverId:id,kind})
}
/** One-time operator seed, supplied as a Worker Secret and removed after sealing. */
export async function seedProfile(env:JobEnv,serverId:string):Promise<void>{
 if(!env.MCP_EXEC_PROFILE_SEED || await getProfile(env.DB,serverId))return
 const seed=JSON.parse(env.MCP_EXEC_PROFILE_SEED) as {serverId:string;username:string;privateKey:string}
 if(seed.serverId!==serverId)return
 if(!/^[a-z_][a-z0-9_-]{0,31}$/.test(seed.username) || seed.username==='root' || !seed.privateKey.includes('BEGIN OPENSSH PRIVATE KEY'))throw new Error('EXEC_PROFILE_REQUIRED')
 const key=readCredentialKey(env);if(!key)throw new Error('KEY_UNAVAILABLE')
 const sealed=await sealCredential(key,seed.privateKey,{serverId,kind:'privateKey',keyVersion:1})
 await env.DB.prepare('INSERT OR IGNORE INTO mcp_exec_profiles(server_id,username,credential,enabled) VALUES(?,?,?,1)').bind(serverId,seed.username,JSON.stringify(sealed)).run()
}
export async function targetSnapshot(env: JobEnv, serverId: string): Promise<string> {
 const server=await getServerPublic(env.DB,serverId), profile=await getProfile(env.DB,serverId)
 if(!server?.fingerprint || !profile?.enabled || profile.username==='root')throw new Error('EXEC_PROFILE_REQUIRED')
 return JSON.stringify({host:server.host,port:server.port,fingerprint:server.fingerprint,serverVersion:server.version,username:profile.username,profileVersion:profile.version})
}
export async function validateJob(env: JobEnv, job: Job, starting = false): Promise<MachineAgent> {
 if(env.MCP_ENABLED!=='true')throw new Error('ACCESS_DENIED')
 const agent=await env.DB.prepare('SELECT * FROM mcp_agents WHERE id=?').bind(job.agent_id).first<MachineAgent>()
 if(!agent || !agent.enabled || agent.expires_at<=Date.now() || agent.version!==job.agent_version)throw new Error('ACCESS_DENIED')
 await checkGrant(env.DB,agent,job.server_id,'command_start')
 if(await targetSnapshot(env,job.server_id)!==job.snapshot)throw new Error('TARGET_CHANGED')
 const admin=await getAdmin(env.DB)
 if(!admin || admin.securityVersion!==job.approval_security_version)throw new Error('APPROVAL_INVALID')
 if(starting && (!job.approval_expires_at || job.approval_expires_at<=Date.now() || job.expires_at<=Date.now()))throw new Error('APPROVAL_EXPIRED')
 return agent
}
export async function submitJob(env: JobEnv, agent: MachineAgent, args: Record<string,unknown>): Promise<Job> {
 const { serverId,command,timeoutSeconds=30,maxOutputBytes=16384 }=args
 if(typeof serverId!=='string' || typeof command!=='string' || !command.trim() || new TextEncoder().encode(command).length>8192 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(command) || !Number.isInteger(timeoutSeconds) || Number(timeoutSeconds)<1 || Number(timeoutSeconds)>120 || !Number.isInteger(maxOutputBytes) || Number(maxOutputBytes)<1024 || Number(maxOutputBytes)>65536)throw new Error('INVALID_ARGUMENTS')
 await checkGrant(env.DB,agent,serverId,'command_submit');await checkGrant(env.DB,agent,serverId,'command_start')
 await seedProfile(env,serverId)
 const snapshot=await targetSnapshot(env,serverId),id=crypto.randomUUID(), now=Date.now()
 const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(command)))).map(b=>b.toString(16).padStart(2,'0')).join('')
 const sealed=await sealJob(env,id,command,'mcpCommand')
 // Bound pending proposals; changing a command means creating a new immutable proposal.
 const r=await env.DB.prepare("INSERT INTO mcp_jobs(id,agent_id,server_id,agent_version,snapshot,command_sealed,command_hash,timeout_seconds,max_output_bytes,status,created_at,expires_at) SELECT ?,?,?,?,?,?,?,?,?, 'pending',?,? WHERE (SELECT count(*) FROM mcp_jobs WHERE agent_id=? AND status IN ('pending','approved','queued','running') AND expires_at>?)<20")
 .bind(id,agent.id,serverId,agent.version,snapshot,sealed,hash,timeoutSeconds,maxOutputBytes,now,now+15*60000,agent.id,now).run()
 if(!r.meta.changes)throw new Error('JOB_LIMIT')
 await audit(env.DB,{agentId:agent.id,tool:'command_submit',serverId,jobId:id,outcome:'pending',started:now})
 return (await getJob(env.DB,id))!
}
export async function jobView(env: JobEnv, job: Job): Promise<Record<string,unknown>> {
 // Recover stale terminal metadata without ever re-executing an interrupted command.
 if(['pending','approved'].includes(job.status) && (job.expires_at<=Date.now() || job.status==='approved' && (job.approval_expires_at??0)<=Date.now())) {
  await env.DB.prepare("UPDATE mcp_jobs SET status='expired',finished_at=? WHERE id=? AND status IN ('pending','approved')").bind(Date.now(),job.id).run();job=(await getJob(env.DB,job.id))!
 }
 if(['queued','running'].includes(job.status) && (job.started_at??job.created_at)+(job.timeout_seconds+60)*1000<Date.now()){
  await env.DB.prepare("UPDATE mcp_jobs SET status='interrupted',outcome='RUNNER_INTERRUPTED',finished_at=? WHERE id=? AND status IN ('queued','running')").bind(Date.now(),job.id).run();job=(await getJob(env.DB,job.id))!
 }
 const { command_sealed,result_sealed,snapshot,...metadata }=job
 return {...metadata,target:JSON.parse(snapshot),command:command_sealed?await openJob(env,job.id,command_sealed,'mcpCommand'):null,result:result_sealed?JSON.parse(await openJob(env,job.id,result_sealed,'mcpOutput')):null}
}
export async function reviewJob(env: JobEnv, id: string, input: Record<string,unknown>): Promise<void> {
 const job=await getJob(env.DB,id),admin=await getAdmin(env.DB)
 if(!job || !admin)throw new Error('JOB_NOT_FOUND')
 if(input.commandHash!==job.command_hash)throw new Error('APPROVAL_INVALID')
 if(input.decision!=='approve' && input.decision!=='reject')throw new Error('INVALID_ARGUMENTS')
 if(job.status!=='pending' || job.expires_at<=Date.now())throw new Error('APPROVAL_EXPIRED')
 if(await targetSnapshot(env,job.server_id)!==job.snapshot)throw new Error('TARGET_CHANGED')
 const owner=await env.DB.prepare('SELECT * FROM mcp_agents WHERE id=?').bind(job.agent_id).first<MachineAgent>()
 if(!owner || owner.version!==job.agent_version)throw new Error('ACCESS_DENIED')
 await checkGrant(env.DB,owner,job.server_id,'command_start')
 const now=Date.now(),approve=input.decision==='approve'
 const r=await env.DB.prepare("UPDATE mcp_jobs SET status=?,approved_at=?,approval_expires_at=?,approved_by=?,approval_security_version=?,finished_at=? WHERE id=? AND status='pending' AND expires_at>?")
 .bind(approve?'approved':'rejected',now,Math.min(now+5*60000,job.expires_at),admin.username,admin.securityVersion,approve?null:now,id,now).run()
 if(!r.meta.changes)throw new Error('APPROVAL_INVALID')
 await audit(env.DB,{agentId:job.agent_id,tool:'command_review',serverId:job.server_id,jobId:id,outcome:approve?'approved':'rejected',started:now})
}
export async function ownedJob(env: JobEnv, agent: MachineAgent, id: string, tool: string): Promise<Job> {
 const job=await getJob(env.DB,id)
 if(!job || job.agent_id!==agent.id)throw new Error('ACCESS_DENIED')
 await checkGrant(env.DB,agent,job.server_id,tool)
 return job
}
export async function cancelJob(env: JobEnv, job: Job): Promise<void> {
 await env.DB.prepare("UPDATE mcp_jobs SET cancel_requested=1,status=CASE WHEN status IN ('pending','approved','queued') THEN 'cancelled' ELSE status END,finished_at=CASE WHEN status IN ('pending','approved','queued') THEN ? ELSE finished_at END WHERE id=? AND status NOT IN ('succeeded','failed','cancelled','timed_out','revoked','interrupted','expired','rejected')").bind(Date.now(),job.id).run()
 if(job.status==='running')await env.COMMAND_JOBS.get(env.COMMAND_JOBS.idFromName(job.id)).fetch(new Request('https://job/cancel',{method:'POST',body:JSON.stringify({jobId:job.id,agentId:job.agent_id})}))
 await audit(env.DB,{agentId:job.agent_id,tool:'command_cancel',serverId:job.server_id,jobId:job.id,outcome:'requested',started:Date.now()})
}
