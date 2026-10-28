import { SshConnection } from '@besh/ssh-core'
import { getProfile,getJob,jobCommand,jobUnit,openJob,sealJob,SYSTEM_PATH,shellQuote,validateJob,TERMINAL,type Job,type JobEnv } from '../domain/mcp-jobs.ts'
import { readCredentialKey } from '../domain/credential-key.ts'
import { openCredential } from '../domain/credentials.ts'
import { resolvePublicTarget } from '../domain/target.ts'
import { audit } from '../domain/mcp-store.ts'

/** Alarm delivery is at least once. D1's queued->running CAS is the execution fence. */
type Connection = Pick<SshConnection,'phase'|'connect'|'authenticateWithKey'|'runCommand'|'close'>
type Connector = (host:string,port:number,fingerprint:string)=>Promise<Connection>
export class CommandJob {
 #ctx: DurableObjectState; #env: JobEnv; #connection: Connection|null=null
 #connector?:Connector
 #running=false; #reason:string|null=null; #stopping:Promise<void>|null=null; #stopConfirmed=false
 constructor(ctx:DurableObjectState,env:JobEnv,connector?:Connector){this.#ctx=ctx;this.#env=env;this.#connector=connector}
 async fetch(request:Request):Promise<Response>{
  if(request.method!=='POST')return new Response(null,{status:405})
  const {jobId,agentId}=await request.json() as {jobId:string;agentId:string}
  if(typeof jobId!=='string' || this.#env.COMMAND_JOBS.idFromName(jobId).toString()!==this.#ctx.id.toString())return new Response(null,{status:403})
  const job=await getJob(this.#env.DB,jobId)
  if(!job || job.agent_id!==agentId)return new Response(null,{status:403})
  if(new URL(request.url).pathname==='/cancel'){
   this.#reason='cancelled';await this.#stop(job)
   return Response.json({cancelRequested:true,remoteStopConfirmed:this.#stopConfirmed})
  }
  if(new URL(request.url).pathname!=='/start')return new Response(null,{status:404})
  return this.#ctx.blockConcurrencyWhile(async()=>{
   try{await validateJob(this.#env,job,true)}catch{return Response.json({error:'APPROVAL_OR_ACCESS_INVALID'},{status:409})}
   // Arm recovery before changing D1 state: a crash can lose neither the alarm nor the job.
   await this.#ctx.storage.put('jobId',job.id);await this.#ctx.storage.setAlarm(Date.now()+100)
   const r=await this.#env.DB.prepare("UPDATE mcp_jobs SET status='queued' WHERE id=? AND status='approved' AND cancel_requested=0 AND approval_expires_at>?").bind(job.id,Date.now()).run()
   return Response.json({queued:!!r.meta.changes},{status:r.meta.changes?202:409})
  })
 }
 async alarm():Promise<void>{
  const id=await this.#ctx.storage.get<string>('jobId');if(!id)return
  const job=await getJob(this.#env.DB,id);if(!job || TERMINAL.includes(job.status))return
  if(this.#running)return // Duplicate delivery while the original event is still alive.
  if(job.status==='running'){
   // Never replay a potentially executed command after an isolate loss.
   await this.#finish(job,'interrupted',{remoteDeadlineEnforced:true},'RUNNER_INTERRUPTED')
   return
  }
  if(job.status!=='queued')return
  this.#running=true
  try{await this.#run(job)}finally{this.#running=false}
 }
 async #stop(job:Job):Promise<void>{
  if(this.#stopping)return this.#stopping
  if(this.#connection?.phase!=='authenticated')return
  const conn=this.#connection
  this.#stopping=(async()=>{
   try{const r=await conn.runCommand(SYSTEM_PATH+'command systemctl --user stop -- '+shellQuote(jobUnit(job.id)),{timeoutMs:5000,maxOutputBytes:1024});if(r.exitCode===0)this.#stopConfirmed=true}catch{/* Remote RuntimeMaxSec remains the backstop. */}
  })().finally(()=>{this.#stopping=null})
  return this.#stopping
 }
 async #guard(job:Job):Promise<void>{
  const live=await getJob(this.#env.DB,job.id)
  if(live?.cancel_requested)this.#reason='cancelled'
  if(this.#reason)throw new Error(this.#reason)
  try{await validateJob(this.#env,job)}catch{this.#reason='revoked';throw new Error('revoked')}
 }
 async #run(job:Job):Promise<void>{
  const db=this.#env.DB,lease='job-'+job.id,begin=Date.now()
  let leased=false,interval:ReturnType<typeof setInterval>|undefined,deadline:ReturnType<typeof setTimeout>|undefined,commandTimer:ReturnType<typeof setTimeout>|undefined
  let checking=false
  try{
   await validateJob(this.#env,job,true)
   const claim=await db.prepare('INSERT OR IGNORE INTO mcp_leases(id,agent_id,expires_at) SELECT ?,?,? WHERE (SELECT count(*) FROM mcp_leases WHERE expires_at>?)<8 AND (SELECT count(*) FROM mcp_leases WHERE agent_id=? AND expires_at>?)<2').bind(lease,job.agent_id,Date.now()+(job.timeout_seconds+45)*1000,Date.now(),job.agent_id,Date.now()).run()
   if(!claim.meta.changes)throw new Error('CONCURRENCY_LIMIT');leased=true
   const cas=await db.prepare("UPDATE mcp_jobs SET status='running',started_at=? WHERE id=? AND status='queued' AND cancel_requested=0").bind(Date.now(),job.id).run()
   if(!cas.meta.changes)return
   await this.#ctx.storage.setAlarm(Date.now()+(job.timeout_seconds+30)*1000)
   await audit(db,{agentId:job.agent_id,tool:'command_start',serverId:job.server_id,jobId:job.id,outcome:'running',started:begin})
   const snapshot=JSON.parse(job.snapshot) as {host:string;port:number;fingerprint:string}
   const {addresses}=await resolvePublicTarget(snapshot.host,{resolve:async hostname=>{
    const url=new URL('https://cloudflare-dns.com/dns-query');url.searchParams.set('name',hostname);url.searchParams.set('type','A')
    const r=await fetch(url,{headers:{Accept:'application/dns-json'},signal:AbortSignal.timeout(5000)});if(!r.ok)throw new Error('DNS_FAILED')
    const v=await r.json() as {Answer?:Array<{type:number;data:string}>};return (v.Answer??[]).filter(x=>x.type===1||x.type===28).map(x=>x.data)
   }})
   await this.#guard(job)
   const create:Connector=this.#connector??(async(host,port,fingerprint)=>{
    const {CloudflareTransportFactory}=await import('../platform/tcp.ts')
    return new SshConnection({factory:new CloudflareTransportFactory(),host,port,connectTimeoutMs:8000,hostKeyPolicy:d=>d.fingerprint===fingerprint})
   })
   const conn=await create(addresses[0],snapshot.port,snapshot.fingerprint);this.#connection=conn
   deadline=setTimeout(()=>{this.#reason??='timed_out';void this.#stop(job).finally(()=>conn.close())},(job.timeout_seconds+20)*1000)
   interval=setInterval(()=>{
    if(checking)return;checking=true
    void this.#guard(job).catch(()=>this.#stop(job)).finally(()=>{checking=false})
   },500)
   await conn.connect();await this.#guard(job)
   const profile=await getProfile(db,job.server_id),key=readCredentialKey(this.#env)
   if(!profile || !key)throw new Error('EXEC_PROFILE_REQUIRED')
   const credential=await openCredential(key,JSON.parse(profile.credential),{serverId:job.server_id,kind:'privateKey'})
   await conn.authenticateWithKey({username:profile.username,privateKey:credential});await this.#guard(job)
   if(!job.command_sealed)throw new Error('COMMAND_CLEARED')
   const command=await openJob(this.#env,job.id,job.command_sealed,'mcpCommand')
   commandTimer=setTimeout(()=>{this.#reason??='timed_out';void this.#stop(job)},job.timeout_seconds*1000)
   const output=await conn.runCommand(jobCommand({...job,timeout_seconds:job.timeout_seconds+3},command),{timeoutMs:(job.timeout_seconds+8)*1000,maxOutputBytes:job.max_output_bytes})
   clearTimeout(commandTimer)
   try{await this.#guard(job)}catch{/* The final reason determines the outcome. */}
   if(this.#reason)await this.#stop(job)
   const state=this.#reason ?? (output.exitCode===0?'succeeded':output.exitCode===null?'interrupted':'failed')
   await this.#finish(job,state,{...output,remoteStopConfirmed:this.#stopConfirmed},state)
  }catch(e){
   if(this.#reason)await this.#stop(job)
   const message=e instanceof Error?e.message:''
   const state=this.#reason ?? (['ACCESS_DENIED','TARGET_CHANGED','APPROVAL_INVALID'].includes(message)?'revoked':message==='APPROVAL_EXPIRED'?'expired':'failed')
   // Do not store arbitrary SSH errors: they may contain credential or host output.
   await this.#finish(job,state,{remoteStopConfirmed:this.#stopConfirmed},state==='failed'?'EXECUTION_FAILED':state)
  }finally{
   if(interval)clearInterval(interval);if(deadline)clearTimeout(deadline);if(commandTimer)clearTimeout(commandTimer)
   await this.#connection?.close().catch(()=>{});this.#connection=null
   if(leased)await db.prepare('DELETE FROM mcp_leases WHERE id=?').bind(lease).run()
  }
 }
 async #finish(job:Job,status:string,result:unknown,outcome:string):Promise<void>{
  const sealed=await sealJob(this.#env,job.id,JSON.stringify(result),'mcpOutput')
  const r=await this.#env.DB.prepare("UPDATE mcp_jobs SET status=?,result_sealed=?,outcome=?,finished_at=? WHERE id=? AND status IN ('queued','running')").bind(status,sealed,outcome,Date.now(),job.id).run()
  if(r.meta.changes)await audit(this.#env.DB,{agentId:job.agent_id,tool:'command_result',serverId:job.server_id,jobId:job.id,outcome:status,started:job.started_at??job.created_at})
 }
}
