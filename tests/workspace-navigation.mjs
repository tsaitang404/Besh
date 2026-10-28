import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';
const server=createServer((req,res)=>{const path=new URL(req.url,'http://test').pathname;try {const file=path==='/'?'/index.html':path;res.setHeader('Content-Type',file.endsWith('.html')?'text/html':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'application/octet-stream');res.end(readFileSync(new URL('../apps/web/dist'+file,import.meta.url)))}catch{res.statusCode=404;res.end()}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const browser=await chromium.launch({headless:true,executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH});
try {
 const page=await browser.newPage({viewport:{width:390,height:844}});
 await page.route('**/api/**',async route=>{
  const p=new URL(route.request().url()).pathname;
  const fixture={
   '/api/auth/bootstrap':{required:false},'/api/auth/session':{authenticated:true},
   '/api/servers':{servers:[{id:'test',name:'Test host',host:'example.com',port:22,username:'test',authMethod:'password',groupId:null,os:null}]},
   '/api/server-groups':{groups:[]},
   '/api/settings':{aiPermission:'confirm',aiConfigured:false,aiProvider:{configured:false,params:{}},ui:{language:'en',theme:'light',terminalFont:14},turnstile:{enabled:false}},
   '/api/sessions':{sessionId:'test',ticket:'synthetic-ticket'},
  }[p];
  await route.fulfill({status:fixture?200:404,contentType:'application/json',body:JSON.stringify(fixture??{})});
 });
 const origin='http://127.0.0.1:'+server.address().port;
 for(const pane of ['terminal','files','assistant']) {
  await page.goto(origin);
  const host=page.locator('.besh-server-list button').filter({hasText:'Test host'});
  await host.waitFor();await host.click();
  await page.locator('.besh-shell[data-mobile-pane="terminal"]').waitFor();
  if(pane!=='terminal')await page.locator('.besh-mobile-nav button').nth(pane==='files'?2:3).click();
  await page.locator(`.besh-shell[data-mobile-pane="${pane}"]`).waitFor();
  // Assistant fills the small screen; close its session from the desktop header.
  if(pane==='assistant')await page.setViewportSize({width:1280,height:844});
  await page.locator('header button[aria-label]').filter({has:page.locator('svg.lucide-x')}).click();
  await page.locator('.besh-shell[data-mobile-pane="servers"]').waitFor();
  if(pane==='assistant')await page.setViewportSize({width:390,height:844});
  assert.equal(await host.isVisible(),true,`server list visible after closing last tab from ${pane}`);
  assert.equal(await page.locator('.besh-mobile-nav button').first().getAttribute('aria-current'),'page');
  console.log('PASS last tab closed from '+pane+' returns to server list');
 }
}finally{await browser.close();await new Promise(r=>server.close(r))}
