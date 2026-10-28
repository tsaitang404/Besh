import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { CommandJob } from '../apps/worker/src/do/command-job.ts';
import { submitJob,reviewJob,getJob,jobView,cancelJob,ownedJob,jobCommand } from '../apps/worker/src/domain/mcp-jobs.ts';
import { findAgent } from '../apps/worker/src/domain/mcp-store.ts';
import { sealCredential } from '../apps/worker/src/domain/credentials.ts';
const sql=new DatabaseSync(':memory:');for(const m of ['0001_init.sql','0003_account_security.sql','0004_mcp.sql','0005_mcp_commands.sql'])sql.exec(readFileSync(new URL('../db/migrations/'+m,import.meta.url),'utf8'));
const db={prepare(q){let v=[];return {bind(...x){v=x;return this},async first(){return sql.prepare(q).get(...v)||null},async all(){return {results:sql.prepare(q).all(...v)}},async run(){return {meta:{changes:Number(sql.prepare(q).run(...v).changes)}}}}},async batch(stmts){sql.exec('BEGIN');try{const r=[];for(const s of stmts)r.push(await s.run());sql.exec('COMMIT');return r}catch(e){sql.exec('ROLLBACK');throw e}}};
const key=crypto.getRandomValues(new Uint8Array(32));const profiles=JSON.stringify(await sealCredential(key,'synthetic-key',{serverId:'s1',kind:'privateKey',keyVersion:1}));
sql.prepare('INSERT INTO admin(id,username,password_hash,salt,iterations,created_at,updated_at) VALUES(1,?,?,?,?,?,?)').run('human-admin','hash','salt',1,0,0);
sql.prepare('INSERT INTO servers(id,name,host,port,username,auth_method,credential,fingerprint,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run('s1','test','93.184.216.34',22,'human','publickey',profiles,'SHA256:fixed',0,0);
sql.prepare('INSERT INTO mcp_agents(id,name,access_common_name,enabled,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').run('a1','machine','a1.access',1,Date.now()+86400000,0,0);
sql.prepare('INSERT INTO mcp_exec_profiles(server_id,username,credential,enabled) VALUES(?,?,?,1)').run('s1','besh-agent',profiles);
for(const t of ['command_submit','command_start','command_status','command_cancel'])sql.prepare('INSERT INTO mcp_grants VALUES(?,?,?)').run('a1','s1',t);
let mode='success',executions=0,release,entered;const instances=new Map();
const env={DB:db,CREDENTIAL_KEY:Buffer.from(key).toString('base64'),MCP_ENABLED:'true',COMMAND_JOBS:{idFromName:id=>({toString:()=>id}),get(id){return instances.get(id.toString())}}};
const agent=await findAgent(db,'a1.access');
function runner(id){
 if(instances.has(id))return instances.get(id);
 const data=new Map();const ctx={id:{toString:()=>id},storage:{async put(k,v){data.set(k,v)},async get(k){return data.get(k)},async setAlarm(v){data.set('alarm',v)}},async blockConcurrencyWhile(fn){return fn()}};
 const connector=async()=>{let phase='kex';return {get phase(){return phase},async connect(){phase='authenticating'},async authenticateWithKey(c){assert.equal(c.username,'besh-agent');assert.equal(c.privateKey,'synthetic-key');phase='authenticated'},async runCommand(command){
  if(command.includes('systemctl --user stop')){release?.();return {stdout:'',exitCode:0,droppedBytes:0}}
  executions++;assert.ok(command.includes('NoNewPrivileges=yes'));assert.ok(command.includes('KillMode=control-group'));
  if(mode==='wait'){entered?.();await new Promise(r=>release=r)}
  return {stdout:'test-output',exitCode:mode==='failure'?7:0,droppedBytes:0};
 },async close(){phase='closed';release?.()}}};
 const obj=new CommandJob(ctx,env,connector);instances.set(id,obj);return obj;
}
const start=async job=>runner(job.id).fetch(new Request('https://job/start',{method:'POST',body:JSON.stringify({jobId:job.id,agentId:job.agent_id})}));
const submit=()=>submitJob(env,agent,{serverId:'s1',command:"printf '%s\\n' 'quote\u0027-test'",timeoutSeconds:3,maxOutputBytes:1024});
const approve=job=>reviewJob(env,job.id,{commandHash:job.command_hash,decision:'approve'});
try{
 const job=await submit();assert.equal(executions,0);assert.equal((await start(job)).status,409);
 await assert.rejects(reviewJob(env,job.id,{commandHash:'wrong',decision:'approve'}),/APPROVAL_INVALID/);
 await approve(job);assert.equal((await start(job)).status,202);assert.equal((await start(job)).status,409);
 await runner(job.id).alarm();assert.equal((await getJob(db,job.id)).status,'succeeded');assert.equal(executions,1);
 await runner(job.id).alarm();assert.equal(executions,1);assert.equal((await start(job)).status,409);
 const view=await jobView(env,await getJob(db,job.id));assert.equal(view.result.stdout,'test-output');assert.equal(view.target.username,'besh-agent');
 const record=JSON.stringify(await getJob(db,job.id));assert.ok(!record.includes('test-output'));assert.ok(!record.includes('printf'));assert.ok(!record.includes('synthetic-key'));
 await assert.rejects(ownedJob(env,{...agent,id:'other'},job.id,'command_status'),/ACCESS_DENIED/);
 const expired=await submit();await approve(expired);sql.prepare('UPDATE mcp_jobs SET approval_expires_at=1 WHERE id=?').run(expired.id);assert.equal((await start(expired)).status,409);
 const changed=await submit();await approve(changed);sql.exec('UPDATE servers SET version=version+1');assert.equal((await start(changed)).status,409);sql.exec('UPDATE servers SET version=version-1');
 const pending=await submit();await cancelJob(env,pending);assert.equal((await getJob(db,pending.id)).status,'cancelled');await assert.rejects(approve(pending));
 mode='wait';const cancel=await submit();await approve(cancel);await start(cancel);
 const ready=new Promise(r=>entered=r);const running=runner(cancel.id).alarm();await ready;
 await cancelJob(env,await getJob(db,cancel.id));await running;
 const cancelled=await jobView(env,await getJob(db,cancel.id));assert.equal(cancelled.status,'cancelled');assert.equal(cancelled.result.remoteStopConfirmed,true);
 const revoke=await submit();await approve(revoke);await start(revoke);const ready2=new Promise(r=>entered=r);const running2=runner(revoke.id).alarm();await ready2;
 sql.exec('UPDATE mcp_agents SET enabled=0,version=version+1');await running2;assert.equal((await getJob(db,revoke.id)).status,'revoked');sql.exec('UPDATE mcp_agents SET enabled=1,version=version-1');
 mode='success';const replay=await submit();await approve(replay);await start(replay);sql.prepare("UPDATE mcp_jobs SET status='running' WHERE id=?").run(replay.id);const before=executions;await runner(replay.id).alarm();assert.equal((await getJob(db,replay.id)).status,'interrupted');assert.equal(executions,before);
 mode='wait';const timed=await submitJob(env,agent,{serverId:'s1',command:'sleep 10',timeoutSeconds:1,maxOutputBytes:1024});await approve(timed);await start(timed);await runner(timed.id).alarm();assert.equal((await getJob(db,timed.id)).status,'timed_out');
 mode='failure';const fail=await submit();await approve(fail);await start(fail);await runner(fail.id).alarm();assert.equal((await getJob(db,fail.id)).status,'failed');
 assert.equal(sql.prepare('SELECT count(*) n FROM mcp_leases').get().n,0);
 assert.ok(sql.prepare("SELECT count(*) n FROM mcp_audit WHERE job_id IS NOT NULL").get().n>0);
 console.log('PASS command jobs: human-only approval/hash, expiry, pinned target/account, one-time execution, encrypted commands/output, owner isolation, pending/running cancel, cgroup stop, live revocation, alarm replay refusal, nonzero exit, audit, lease cleanup');
}finally{sql.close()}
