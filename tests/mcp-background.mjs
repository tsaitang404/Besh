import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { rmSync } from 'node:fs'
import { startScript, pollScript } from '../apps/worker/src/domain/mcp-background.ts'
const ids=[]
const run=script=>execFileSync('sh',['-c',script],{encoding:'utf8'})
const poll=(id,offset=0,cancel=false)=>run(pollScript(id,offset,1024,cancel)).trim().split('\n')
try {
 const id=randomUUID();ids.push(id)
 assert.match(run(startScript(id,"printf 'first'; sleep 3; printf 'last'; exit 7",30)),/started/)
 let p=poll(id);assert.equal(p[0],'running');assert.equal(Buffer.from(p.slice(3).join(''),'base64').toString(),'first')
 await new Promise(r=>setTimeout(r,3500));p=poll(id,5);assert.equal(p[0],'completed');assert.equal(p[1],'7');assert.equal(Buffer.from(p.slice(3).join(''),'base64').toString(),'last')
 const cancelId=randomUUID();ids.push(cancelId)
 run(startScript(cancelId,'sleep 60; echo should-not-run',120));p=poll(cancelId,0,true);assert.equal(p[0],'cancelled');assert.equal(poll(cancelId)[0],'cancelled')
 const timeoutId=randomUUID();ids.push(timeoutId)
 run(startScript(timeoutId,'sleep 60',1));await new Promise(r=>setTimeout(r,1500));p=poll(timeoutId);assert.equal(p[0],'completed');assert.equal(p[1],'124')
 assert.notEqual(spawnSync('sh',['-c',pollScript(randomUUID(),0,1024)]).status,0)
 console.log('Background task: incremental output, exit code, cancellation and timeout passed')
} finally { for(const id of ids)rmSync('/tmp/besh-mcp-'+id,{recursive:true,force:true}) }
