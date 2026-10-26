import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { workersAiProvider, recordWorkersAiRequest } from '../apps/worker/src/domain/workers-ai.ts';
import { chat } from '../apps/worker/src/domain/ai-chat.ts';
function database() {
  const sql=new DatabaseSync(':memory:');
  sql.exec(readFileSync(new URL('../db/migrations/0002_workers_ai_budget.sql',import.meta.url),'utf8'));
  return {prepare(query){let params=[];return {bind(...values){params=values;return this;},async first(){return sql.prepare(query).get(...params)||null;}};}};
}
const db=database();const claims=await Promise.allSettled(Array.from({length:45},()=>recordWorkersAiRequest(db,0)));
assert.equal(claims.filter(c=>c.status==='fulfilled').length,45);
await recordWorkersAiRequest(db,86400000);console.log('PASS more than 40 requests accepted and UTC counter rollover');
let called=0;
const provider=workersAiProvider({DB:database(),AI:{async run(model,body){called++;assert.equal(model,'@cf/qwen/qwen3-30b-a3b-fp8');assert.equal(body.max_tokens,2048);assert(body.tools);return {choices:[{message:{content:'BESH_AI_OK'}}],usage:{prompt_tokens:5,completion_tokens:4}};}}});
const reply=await chat(provider,[{role:'user',content:'test'}]);assert.equal(reply.content,'BESH_AI_OK');assert.equal(reply.usage.promptTokens,5);assert.equal(called,1);console.log('PASS native JSON transport and token accounting');
const encoder=new TextEncoder();const chunks=[
 {choices:[{delta:{content:'Hello'}}]},
 {choices:[{delta:{tool_calls:[{index:0,id:'call1',function:{name:'run_command',arguments:'{"command":"printf'}}]}}]},
 {choices:[{delta:{tool_calls:[{index:0,function:{arguments:' ok","purpose":"test"}'}}]}}]},
 {choices:[{delta:{},finish_reason:'tool_calls'}]},
 {response:null,usage:{prompt_tokens:10,completion_tokens:12}},
];
const streaming=workersAiProvider({DB:database(),AI:{async run(){return new ReadableStream({start(c){for(const chunk of chunks)c.enqueue(encoder.encode('data: '+JSON.stringify(chunk)+'\n\n'));c.enqueue(encoder.encode('data: [DONE]\n\n'));c.close();}});}}});
let text='';const streamed=await chat(streaming,[{role:'user',content:'test'}],{onText:part=>text+=part});assert.equal(text,'Hello');assert.equal(streamed.toolCalls[0].name,'run_command');assert.equal(JSON.parse(streamed.toolCalls[0].arguments).command,'printf ok');assert.equal(streamed.usage.completionTokens,12);console.log('PASS SSE fragments, tool arguments and stream usage');
let cancelled=false;const controller=new AbortController();
const slow=workersAiProvider({DB:database(),AI:{async run(){return new ReadableStream({cancel(){cancelled=true;}});}}});
const waiting=chat(slow,[{role:'user',content:'test'}],{signal:controller.signal,onText:()=>{}});setTimeout(()=>controller.abort(),10);await assert.rejects(waiting);assert(cancelled);console.log('PASS cancellation releases native stream');
assert.equal(workersAiProvider({DB:database()}),null);console.log('PASS missing binding leaves custom-only mode available');

const premature=workersAiProvider({DB:database(),AI:{async run(){return new Response('data: '+JSON.stringify({response:null,usage:{prompt_tokens:1,completion_tokens:1}})+'\n\ndata: [DONE]\n\n',{headers:{'content-type':'text/event-stream'}});}}});
await assert.rejects(chat(premature,[{role:'user',content:'test'}],{onText:()=>{}}),/畸形/);
console.log('PASS terminal metadata cannot authorize incomplete tool output');
const rawJson=workersAiProvider({DB:database(),AI:{async run(){return Response.json({result:{choices:[{message:{content:'RAW_OK'}}]}});}}});
assert.equal((await chat(rawJson,[{role:'user',content:'test'}])).content,'RAW_OK');console.log('PASS raw binding JSON response envelope');

const alreadyUsed=database();for(let i=0;i<45;i++)await recordWorkersAiRequest(alreadyUsed);
const uncapped=workersAiProvider({DB:alreadyUsed,AI:{async run(){return {choices:[{message:{content:'AFTER_40_OK'}}]};}}});
assert.equal((await chat(uncapped,[{role:'user',content:'test'}])).content,'AFTER_40_OK');
console.log('PASS inference remains available after 45 daily calls');
const statsOffline=workersAiProvider({DB:{prepare(){throw Error('stats unavailable');}},AI:{async run(){return {choices:[{message:{content:'STATS_OPTIONAL'}}]};}}});
assert.equal((await chat(statsOffline,[{role:'user',content:'test'}])).content,'STATS_OPTIONAL');
console.log('PASS request statistics failure does not block inference');
