import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {readFileSync} from 'node:fs'
import {chromium} from 'playwright'
const server=createServer((req,res)=>{try{const p=new URL(req.url,'http://test').pathname;const file=p==='/'?'/index.html':p;res.setHeader('Content-Type',file.endsWith('.html')?'text/html':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'application/octet-stream');res.end(readFileSync(new URL('../apps/web/dist'+file,import.meta.url)))}catch{res.statusCode=404;res.end()}})
await new Promise(r=>server.listen(0,'127.0.0.1',r))
const browser=await chromium.launch({headless:true,executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH})
try{
 const page=await browser.newPage({viewport:{width:1280,height:900}})
 await page.addInitScript(()=>localStorage.setItem('besh:lang','en-US'))
 let settings={aiPermission:'confirm',aiConfigured:true,aiProvider:{configured:true,hasKey:true,baseUrl:'https://old.example/v1',model:'test-model',params:{contextWindow:32000,maxOutput:4000,inputs:{text:true,image:false},effort:'default'}},ui:{language:'en-US',theme:'light',terminalFont:14},turnstile:{enabled:false,siteKey:'',hasSecret:false}}
 const writes=[];let failNext=false,inflight=0,maxInflight=0,blockFirst,firstStarted
 const firstReady=new Promise(r=>firstStarted=r),firstGate=new Promise(r=>blockFirst=r)
 await page.route('**/api/**',async route=>{
  const request=route.request(),p=new URL(request.url()).pathname
  if(p==='/api/settings'&&request.method()==='PUT'){
   const data=request.postDataJSON();writes.push(data);inflight++;maxInflight=Math.max(maxInflight,inflight)
   if(writes.length===1){firstStarted();await firstGate}
   if(failNext){failNext=false;inflight--;await route.fulfill({status:500,json:{error:{code:'INTERNAL',message:'synthetic failure'}}});return}
   settings={...settings,aiProvider:{...settings.aiProvider,...data.aiProvider,hasKey:true,params:data.aiProvider.params??settings.aiProvider.params}}
   delete settings.aiProvider.apiKey
   inflight--;await route.fulfill({json:settings});return
  }
  const fixture={'/api/auth/bootstrap':{required:false},'/api/auth/session':{authenticated:true},'/api/servers':{servers:[{id:'test',name:'Test host',host:'example.com',port:22,username:'test',authMethod:'password',groupId:null,os:null}]},'/api/sessions':{sessionId:'test',ticket:'synthetic-ticket'},'/api/server-groups':{groups:[]},'/api/settings':settings}[p]
  await route.fulfill({status:fixture?200:404,json:fixture??{}})
 })
 await page.routeWebSocket('**/api/sessions/**/terminal?*',ws=>ws.onMessage(raw=>{
   const message=JSON.parse(String(raw));
   if(message.type==='resize')ws.send(JSON.stringify({type:'ready'}));
   if(message.type==='ai.history')ws.send(JSON.stringify({type:'ai.messages',id:message.id,entries:[{kind:'result',command:'synthetic-output',output:Array.from({length:40},(_,i)=>'line '+i).join('\n'),exitCode:0}]}));
 }))
 await page.goto('http://127.0.0.1:'+server.address().port)
 await page.getByRole('button',{name:'Settings',exact:true}).click()
 await page.getByRole('tab',{name:'AI assistant',exact:true}).click()
 const endpoint=page.locator('#ai-base-url'),key=page.locator('#ai-key')
 await endpoint.fill('https://new.example/v1');await key.focus();await firstReady
 await key.fill('synthetic-key-one');await endpoint.focus()
 await key.fill('synthetic-key-two');await endpoint.focus()
 assert.equal(writes.length,1,'later saves wait behind the first request')
 blockFirst()
 await page.waitForFunction(()=>document.querySelector('#ai-key')?.value==='')
 assert.ok(writes.length>=3);assert.equal(maxInflight,1)
 assert.equal(writes[1].aiProvider.apiKey,'synthetic-key-one');assert.equal(writes.at(-1).aiProvider.apiKey,'synthetic-key-two')
 assert.ok(writes.every(w=>w.aiProvider.params===undefined),'blur leaves advanced parameters untouched')
 assert.equal(settings.aiProvider.baseUrl,'https://new.example/v1')
 assert.equal(settings.aiProvider.params.contextWindow,32000)
 await page.getByRole('button',{name:'Close settings',exact:true}).click()
 await page.getByRole('button',{name:'Settings',exact:true}).click()
 await page.getByRole('tab',{name:'AI assistant',exact:true}).click()
 assert.equal(await endpoint.inputValue(),'https://new.example/v1')
 failNext=true
 const failed=page.waitForResponse(r=>r.url().endsWith('/api/settings')&&r.status()===500)
 await endpoint.fill('https://failure.example/v1');await key.focus();await failed
 const recovered=page.waitForResponse(r=>r.url().endsWith('/api/settings')&&r.request().method()==='PUT'&&r.request().postDataJSON()?.aiProvider?.baseUrl==='https://recovered.example/v1'&&r.status()===200)
 await endpoint.fill('https://recovered.example/v1');await key.focus();await recovered
 assert.equal(settings.aiProvider.baseUrl,'https://recovered.example/v1')
 await page.getByRole('button',{name:/Advanced/}).click()
 await page.locator('#ai-context').fill('64K')
 await key.fill('synthetic-key-three');await endpoint.focus()
 await page.waitForFunction(()=>document.querySelector('#ai-key')?.value==='')
 assert.equal(settings.aiProvider.params.contextWindow,32000,'advanced draft not committed on key blur')
 const savedParams=page.waitForResponse(r=>r.url().endsWith('/api/settings')&&r.request().postDataJSON()?.aiProvider?.params!==undefined)
 await page.getByRole('button',{name:'Save model settings',exact:true}).click();await savedParams
 assert.equal(settings.aiProvider.params.contextWindow,64000)
 console.log('PASS failed autosave recovers; advanced parameters require explicit save')
 await page.getByRole('tab',{name:'Account',exact:true}).click()
 assert.equal(await page.getByRole('tab',{name:'Account',exact:true}).getAttribute('aria-selected'),'true')
 await page.getByRole('button',{name:'Close settings',exact:true}).click()
 await page.locator('.besh-server-list button').filter({hasText:'Test host'}).click()
 const fold=page.getByRole('button',{name:'Show 40 lines',exact:true});await fold.waitFor()
 assert.equal(await fold.getAttribute('aria-expanded'),'false')
 assert.ok(await page.locator('pre').filter({hasText:'line 39'}).evaluate(el=>el.parentElement.clientHeight<=168))
 await fold.click()
 const collapse=page.getByRole('button',{name:'Collapse',exact:true});await collapse.waitFor()
 assert.equal(await collapse.getAttribute('aria-expanded'),'true');assert.ok(await page.locator('pre').filter({hasText:'line 39'}).evaluate(el=>el.parentElement.clientHeight<=420));await collapse.click();await fold.waitFor()
 console.log('PASS long tool output folds, expands into bounded view and collapses again')
 console.log('PASS upstream merge UI: queued endpoint/key saves, edits during in-flight saves, advanced params preserved, close/reopen persistence and account tab retained')
}finally{await browser.close();await new Promise(r=>server.close(r))}
