import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { chromium } from 'playwright'
const server = createServer((req, res) => {
  try {
    const path = new URL(req.url, 'http://test').pathname
    const file = path === '/' ? '/index.html' : path
    res.setHeader('Content-Type', file.endsWith('.html') ? 'text/html' : file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'application/octet-stream')
    res.end(readFileSync(new URL('../apps/web/dist' + file, import.meta.url)))
  } catch { res.statusCode = 404; res.end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
let browser
try {
 browser = await chromium.launch({headless:true,executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH})
 for (const width of [390,1280]) {
  const page=await browser.newPage({viewport:{width,height:844},hasTouch:width===390})
  await page.addInitScript(()=>localStorage.setItem('besh:lang','en-US'))
  const hosts=['Alpha','Beta'].map(name=>({id:name,name,host:'example.com',port:22,username:'test',authMethod:'password',groupId:null,os:null}))
  await page.route('**/api/**',async route=>{
   const p=new URL(route.request().url()).pathname
   const fixture={
    '/api/auth/bootstrap':{required:false},'/api/auth/session':{authenticated:true},
    '/api/servers':{servers:hosts},'/api/server-groups':{groups:[]},
    '/api/settings':{aiPermission:'confirm',aiConfigured:true,aiProvider:{configured:true,params:{inputs:{image:true}}},ui:{language:'en-US',theme:'light',terminalFont:14},turnstile:{enabled:false}},
   }[p] ?? (p==='/api/sessions'?{sessionId:route.request().postDataJSON().serverId,ticket:'synthetic'}:undefined)
   await route.fulfill({status:fixture?200:404,json:fixture??{}})
  })
  const sockets=new Map(),asks=[]
  await page.routeWebSocket('**/api/sessions/**/terminal?*',ws=>{
   const id=new URL(ws.url()).pathname.split('/')[3];sockets.set(id,ws);let ready=false
   ws.onMessage(raw=>{const m=JSON.parse(String(raw));if(m.type==='resize'&&!ready){ready=true;ws.send(JSON.stringify({type:'ready'}))}if(m.type==='ai.ask')asks.push([id,m.text])})
  })
  await page.goto('http://127.0.0.1:'+server.address().port)
  const nav=async index=>{if(width===390)await page.locator('.besh-mobile-nav button').nth(index).click()}
  const open=async name=>{await nav(0);await page.locator('.besh-server-list button').filter({hasText:name}).click();await nav(3)}
  const tab=async name=>{await nav(1);await page.locator('header button[aria-pressed]').filter({hasText:name}).click();await nav(3)}
  await open('Alpha')
  const a=page.locator('[data-inspector="Alpha"]'),b=page.locator('[data-inspector="Beta"]')
  await a.locator('textarea').fill('alpha unsent')
  await a.locator('input[type=file]').setInputFiles({name:'alpha.txt',mimeType:'text/plain',buffer:Buffer.from('alpha attachment')})
  await a.getByText('alpha.txt',{exact:true}).waitFor()
  const original=await a.locator('textarea').elementHandle()
  await open('Beta')
  await b.locator('textarea').fill('beta unsent')
  await b.locator('input[type=file]').setInputFiles({name:'beta.txt',mimeType:'text/plain',buffer:Buffer.from('beta attachment')})
  await b.getByText('beta.txt',{exact:true}).waitFor()
  await b.locator('textarea').focus()
  // Updating a hidden panel must not focus its composer or disturb the active one.
  sockets.get('Alpha').send(JSON.stringify({type:'ai.conversationList',current:'default',conversations:[]}))
  assert.equal(await b.locator('textarea').evaluate(el=>el===document.activeElement),true)
  await tab('Alpha')
  assert.equal(await a.locator('textarea').inputValue(),'alpha unsent')
  assert.equal(await a.locator('textarea').evaluate((el,old)=>el===old,original),true)
  assert.equal(await a.getByText('alpha.txt',{exact:true}).count(),1)
  assert.equal(await b.isVisible(),false)
  assert.equal(await a.locator('textarea').evaluate(el=>el===document.activeElement),false,'tab switch does not steal focus')
  await a.locator('textarea').press('Enter')
  await page.waitForTimeout(40)
  assert.equal(asks.length,1);assert.equal(asks[0][0],'Alpha');assert.ok(asks[0][1].includes('alpha attachment'))
  await tab('Beta')
  assert.equal(await b.locator('textarea').inputValue(),'beta unsent')
  assert.equal(await b.getByText('beta.txt',{exact:true}).count(),1)
  await b.locator('textarea').press('Enter')
  await page.waitForTimeout(40)
  assert.equal(asks.length,2);assert.equal(asks[1][0],'Beta');assert.ok(asks[1][1].includes('beta attachment'))
  const hash='SHA256:'+('abcdef0123456789'.repeat(16))
  sockets.get('Beta').send(JSON.stringify({type:'error',code:'HOST_KEY_CHANGED',message:'synthetic',hostKey:{stored:hash,presented:'/very/long/path/'+('nested_'.repeat(80))}}))
  const dialog=page.getByRole('alertdialog');await dialog.waitFor()
  const description=dialog.locator('[data-slot="alert-dialog-description"]')
  assert.equal(await description.evaluate(el=>getComputedStyle(el).whiteSpace),'pre-line')
  assert.equal(await description.evaluate(el=>el.scrollWidth<=el.clientWidth+1),true,'fingerprint stays inside description')
  assert.equal(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth+1),true,'dialog contents stay inside card')
  assert.equal(await dialog.evaluate(el=>el.getBoundingClientRect().right<=innerWidth),true)
  await page.getByRole('button',{name:'Cancel',exact:true}).click()
  console.log('PASS '+width+'px: independent drafts/attachments survive tabs, correct send target, focus retained, long fingerprint wraps')
  await page.close()
 }
} finally {await browser?.close();await new Promise(resolve=>server.close(resolve))}
