import assert from 'node:assert/strict';import {createServer} from 'node:http';import {readFileSync} from 'node:fs';import {chromium} from 'playwright';
const server=createServer((req,res)=>{try{const p=new URL(req.url,'http://test').pathname,file=p==='/'?'/index.html':p;res.setHeader('Content-Type',file.endsWith('.html')?'text/html':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'application/octet-stream');res.end(readFileSync(new URL('../apps/web/dist'+file,import.meta.url)))}catch{res.statusCode=404;res.end()}});await new Promise(r=>server.listen(0,'127.0.0.1',r));
const browser=await chromium.launch({headless:true,executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH});
try{for(const width of [390,1280]){
 const page=await browser.newPage({viewport:{width,height:844}});let status='pending',approved=0,cancelled=0;
 const command="printf '%s' '<img src=x onerror=alert(1)>'";
 const job=()=>({id:'11111111-1111-4111-8111-111111111111',agent_id:'test-agent',server_id:'test',status,command,command_hash:'bound-hash',timeout_seconds:10,max_output_bytes:1024,target:{host:'example.com',port:22,username:'besh-agent',fingerprint:'SHA256:fixed'},cancel_requested:0});
 await page.route('**/api/**',async route=>{const path=new URL(route.request().url()).pathname;let fixture;
 if(path==='/api/auth/bootstrap')fixture={required:false};else if(path==='/api/auth/session')fixture={authenticated:true};else if(path==='/api/servers')fixture={servers:[]};else if(path==='/api/server-groups')fixture={groups:[]};else if(path==='/api/settings')fixture={aiPermission:'confirm',aiConfigured:false,aiProvider:{configured:false,baseUrl:'',model:'',params:{}},ui:{language:'en',theme:'light',terminalFont:14},turnstile:{enabled:false}};
 else if(path==='/api/mcp/jobs')fixture={jobs:[job()]};else if(path.endsWith('/review')){assert.deepEqual(route.request().postDataJSON(),{commandHash:'bound-hash',decision:'approve'});approved++;status='approved';fixture={ok:true}}else if(path.endsWith('/cancel')){cancelled++;status='cancelled';fixture={ok:true}}
 await route.fulfill({status:fixture?200:404,contentType:'application/json',body:JSON.stringify(fixture??{})});});
 await page.goto('http://127.0.0.1:'+server.address().port+'/#mcp-jobs');
 const approve=page.getByRole('button',{name:/Review and approve|审核并批准/});await approve.waitFor();assert.equal(approved,0);
 assert.equal(await page.locator('img[src="x"]').count(),0);await approve.click();
 const confirm=page.getByRole('button',{name:/Approve once|批准一次/});await confirm.waitFor();assert.equal(approved,0);assert.ok((await page.getByRole('alertdialog').innerText()).includes(command));await confirm.click();
 await page.getByText('test-agent · approved',{exact:true}).waitFor();assert.equal(approved,1);
 await page.getByRole('button',{name:/^Cancel job$|^取消任务$/}).click();await page.getByText('test-agent · cancelled',{exact:true}).waitFor();assert.equal(cancelled,1);
 console.log('PASS '+width+'px command approval UI: deep link, exact command preview, escaping, explicit one-time hash-bound approval, cancel');await page.close();
}}finally{await browser.close();await new Promise(r=>server.close(r))}
