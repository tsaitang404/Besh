import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { TransferQueue } from '../apps/web/src/lib/transfer-queue.ts';
import { handleUpdateServer } from '../apps/worker/src/http/servers.ts';
import { updateServer } from '../apps/worker/src/domain/server-store.ts';
import { sealCredential, openCredential } from '../apps/worker/src/domain/credentials.ts';
const tick=()=>new Promise(r=>setTimeout(r,0));
let enteredResolve;const entered=new Promise(r=>enteredResolve=r);let rejectChunk;let first=true;const staged=new Map();let serial=0;let committed;
const q=new TransferQueue({
 beginUpload:async()=>{const id=String(++serial);staged.set(id,[]);return id;},
 writeChunk:async(_p,id,offset,data)=>{if(id==='1'&&offset===2&&first){first=false;enteredResolve();await new Promise((_r,reject)=>rejectChunk=reject);}const b=staged.get(id);if(!b)throw Error('upload aborted');for(let i=0;i<data.length;i++)b[offset+i]=data[i];},
 abortUpload:async(_p,id)=>{staged.delete(id);rejectChunk?.(Error('upload aborted'));},
 endUpload:async(_p,id)=>{committed=Uint8Array.from(staged.get(id));},readRange:async()=>new Uint8Array()
},{chunkSize:2,attempts:1,sleep:async()=>{}});
const [item]=q.addUploads([{name:'file',path:'/file',bytes:new TextEncoder().encode('abcdef')}]);await entered;await q.cancel(item.id);while(q.running)await tick();q.retry(item.id);while(q.running)await tick();
assert.deepEqual([...committed],[97,98,99,100,101,102]);console.log('PASS: canceled upload restarts without corrupting bytes');
const sql=new DatabaseSync(':memory:');sql.exec(readFileSync(new URL('../db/migrations/0001_init.sql',import.meta.url),'utf8'));
const key=crypto.getRandomValues(new Uint8Array(32));const sealed=await sealCredential(key,'dummy-password',{serverId:'s1',kind:'password',keyVersion:1});
sql.prepare('INSERT INTO servers(id,name,host,port,username,auth_method,credential,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)').run('s1','original','example.com',22,'root','password',JSON.stringify(sealed),0,0);
const db={prepare(query){let values=[];return {bind(...v){values=v;return this;},async first(){return sql.prepare(query).get(...values)||null;},async run(){const r=sql.prepare(query).run(...values);return {meta:{changes:r.changes}};}};}};
const common={host:'example.com',port:22,username:'root',authMethod:'password',groupId:null,expectedVersion:1,now:1};
const results=await Promise.allSettled([updateServer(db,'s1',{...common,name:'edit-A'}),updateServer(db,'s1',{...common,name:'edit-B'})]);assert.equal(results.filter(x=>x.status==='fulfilled').length,1);assert.equal(results.filter(x=>x.status==='rejected').length,1);console.log('PASS: concurrent stale edit rejected');
const response=await handleUpdateServer(new Request('https://besh.test/api/servers/s1',{method:'PUT',body:JSON.stringify({...common,name:'changed',authMethod:'publickey',credential:'',version:2})}),{DB:db,CREDENTIAL_KEY:Buffer.from(key).toString('base64')},'s1',{resolve:async()=>['93.184.216.34']});
assert.equal(response.status,400);assert.equal(sql.prepare('select auth_method from servers').get().auth_method,'password');console.log('PASS: auth method change requires a new credential');
