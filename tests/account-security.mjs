import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { totp, matchTotp } from '../apps/worker/src/domain/totp.ts';
import { createAdmin, getAdmin, insertSession, updateAdminPassword } from '../apps/worker/src/domain/admin-store.ts';
import { hashPassword, createSessionToken, hashSessionToken } from '../apps/worker/src/domain/auth.ts';
import { handleGetSettings } from '../apps/worker/src/http/settings.ts';
import { handleLogin, handleSession, handleBootstrapStatus, requireAdmin } from '../apps/worker/src/http/auth.ts';
import { handleAccountSecurity, verifySecondFactor } from '../apps/worker/src/http/account-security.ts';
const sql = new DatabaseSync(':memory:');
for (const migration of ['0001_init.sql', '0002_workers_ai_budget.sql', '0003_account_security.sql']) sql.exec(readFileSync(new URL(`../db/migrations/${migration}`, import.meta.url), 'utf8'));
const db = {
 prepare(query) { let values = []; return {
  bind(...args) { values = args; return this; },
  async first() { return sql.prepare(query).get(...values) ?? null; },
  async all() { return { results: sql.prepare(query).all(...values) }; },
  async run() { const r = sql.prepare(query).run(...values); return { success: true, meta: { changes: Number(r.changes) } }; },
 }; },
 async batch(statements) { sql.exec('BEGIN'); try { const results = []; for (const stmt of statements) results.push(await stmt.run()); sql.exec('COMMIT'); return results; } catch (e) { sql.exec('ROLLBACK'); throw e; } }
};
const password = 'test-password-only', key = crypto.getRandomValues(new Uint8Array(32));
const env = { DB: db, CREDENTIAL_KEY: Buffer.from(key).toString('base64') };
await createAdmin(db, { ...await hashPassword(password), username: 'admin' });
let admin = await getAdmin(db), session = await createSessionToken();
await insertSession(db, { hash: session.hash, createdAt: Date.now(), expiresAt: session.expiresAt }, admin);
const request = (path, body, cookie = session.token) => new Request(`https://besh.test/api/auth/security/${path}`, { method: 'POST', headers: { Cookie: `besh_session=${cookie}` }, body: JSON.stringify(body) });
const call = (path, body) => handleAccountSecurity(request(path, body), env, path);
// RFC 6238 SHA-1 vector, reduced to six digits.
assert.equal(await totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1), '287082');
assert.equal(await matchTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '287082', 59000), 1);
assert.equal(await matchTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '287082', 180000), null);
assert.equal((await call('totp/setup', { password: 'wrong' })).status, 401);
assert.equal((await handleAccountSecurity(request('totp/setup', {password}, 'bad'), env, 'totp/setup')).status, 401);
let response = await call('totp/setup', { password }); assert.equal(response.status, 200);
const setup = await response.json();
assert.equal(sql.prepare('SELECT totp FROM account_security').get().totp, null);
assert.ok(!sql.prepare('SELECT payload FROM auth_challenges').get().payload.includes(setup.secret));
const step = Math.floor(Date.now() / 30000), code = await totp(setup.secret, step);
response = await call('totp/enable', { challengeId: setup.challengeId, code }); assert.equal(response.status, 200);
const { recoveryCodes } = await response.json(); assert.equal(recoveryCodes.length, 10);
assert.ok(!sql.prepare('SELECT totp FROM account_security').get().totp.includes(setup.secret));
assert.equal(sql.prepare('SELECT count(*) AS n FROM admin_sessions WHERE token_hash = ?').get(session.hash).n, 0);
assert.equal(await verifySecondFactor(env, code), false, 'enrollment code cannot be reused');
assert.equal(await verifySecondFactor(env, recoveryCodes[0]), true);
assert.equal(await verifySecondFactor(env, recoveryCodes[0]), false);
const login = (extra = {}) => handleLogin(new Request('https://besh.test/api/auth/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password, ...extra }) }), env);
response = await login({ password: 'wrong' }); assert.equal(response.status, 401);
response = await login(); assert.equal(response.status, 200); assert.equal(response.headers.get('Set-Cookie'), null);
const secondStep = await response.json();
assert.deepEqual(secondStep.methods, { passkey: false, totp: true });
assert.equal(secondStep.authenticated, false);
assert.ok(!sql.prepare("SELECT id FROM auth_challenges WHERE purpose = 'login-step'").get().id.includes(secondStep.stageToken));
assert.equal((await handleAccountSecurity(request('status', {}, secondStep.stageToken), env, 'status')).status, 401, 'password proof is not an admin session');
assert.equal((await call('login/verify', { code: recoveryCodes[1] })).status, 401, 'second factor requires password proof');
assert.equal((await call('login/verify', { stageToken: secondStep.stageToken, code: 'invalid' })).status, 401);
const wrongOrigin = new Request('https://other.test/api/auth/security/login/verify', {method:'POST',body:JSON.stringify({stageToken:secondStep.stageToken,code:recoveryCodes[1]})});
assert.equal((await handleAccountSecurity(wrongOrigin, env, 'login/verify')).status, 401, 'password proof is origin-bound');
response = await call('login/verify', {stageToken:secondStep.stageToken,code:recoveryCodes[1]}); assert.equal(response.status, 200);
session.token = response.headers.get('Set-Cookie').split(';')[0].split('=')[1];
assert.equal((await call('login/verify', {stageToken:secondStep.stageToken,code:recoveryCodes[2]})).status, 401, 'password proof is single-use');
const expiredStep = await (await login()).json();
sql.prepare('UPDATE auth_challenges SET expires_at = 0 WHERE id = ?').run(await hashSessionToken(expiredStep.stageToken));
assert.equal((await call('login/verify', {stageToken:expiredStep.stageToken,code:recoveryCodes[2]})).status, 401);
// One-time challenge and session binding, with registration cancellation.
response = await call('register/options', { password, code: recoveryCodes[2] }); assert.equal(response.status, 200);
const reg = await response.json();
assert.equal((await call('register/verify', { challengeId: reg.challengeId, response: {} })).status, 400);
assert.equal((await call('register/verify', { challengeId: reg.challengeId, response: {} })).status, 401);
assert.equal((await call('passkey/options', {})).status, 401, 'passkeys cannot bypass password verification');
const staleStep = await (await login()).json();
const oldAdmin = await getAdmin(db);
response = await call('totp/disable', { password, code: recoveryCodes[3] }); assert.equal(response.status, 200);
assert.equal((await call('login/verify', {stageToken:staleStep.stageToken,code:recoveryCodes[4]})).status, 401, 'security changes revoke pending password proofs');
assert.equal(sql.prepare('SELECT count(*) AS n FROM recovery_codes').get().n, 0);
assert.equal(sql.prepare('SELECT totp FROM account_security').get().totp, null);
assert.equal(await insertSession(db, {hash: 'stale', createdAt: 0, expiresAt: Date.now()+10000}, oldAdmin), false);
assert.equal(await updateAdminPassword(db, await hashPassword('new-test-password'), oldAdmin), false, 'stale password reauthentication cannot bypass newly changed security');
for (let i=0; i<35; i++) response = await call('passkey/options', {});
assert.equal(response.status, 429);
console.log('PASS: RFC TOTP, encrypted setup, reauthentication, replay prevention, recovery codes, required second factor, session revocation, challenge expiry/consumption, stale credentials, rate limit');

// A real Chromium WebAuthn ceremony with a virtual FIDO2 authenticator.
const { createServer } = await import('node:http');
const { chromium } = await import('playwright');
sql.exec('DELETE FROM auth_limits');
admin = await getAdmin(db); session = await createSessionToken();
await insertSession(db, {hash: session.hash, createdAt: Date.now(), expiresAt: session.expiresAt}, admin);
const server = createServer(async (req, res) => {
 try {
  const address = server.address(), origin = `http://localhost:${address.port}`;
  if (req.url === '/') { res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>WebAuthn integration</title>'); return; }
  const pathname = new URL(req.url, origin).pathname;
  if (pathname === '/ui' || pathname.startsWith('/assets/')) {
   const asset = pathname === '/ui' ? '/index.html' : '/assets/' + pathname.split('/').at(-1);
   res.setHeader('Content-Type', asset.endsWith('.html') ? 'text/html' : asset.endsWith('.js') ? 'text/javascript' : asset.endsWith('.css') ? 'text/css' : 'application/octet-stream');
   res.end(readFileSync(new URL('../apps/web/dist'+asset, import.meta.url))); return;
  }
  let body = ''; for await (const chunk of req) body += chunk;
  const request = new Request(origin + req.url, { method: req.method, headers: req.headers, ...(req.method === 'POST' ? {body} : {}) });
  const path = req.url.slice('/api/auth/security/'.length);
  let result;
  if (req.url === '/api/auth/login') result = await handleLogin(request, env);
  else if (req.url === '/api/auth/bootstrap') result = await handleBootstrapStatus(request, env);
  else if (req.url === '/api/auth/session') result = await handleSession(request, env);
  else if (req.url === '/api/auth/turnstile') result = Response.json({enabled:false,siteKey:''});
  else if (req.url.startsWith('/api/auth/security/')) result = await handleAccountSecurity(request, env, path);
  else {
   result = await requireAdmin(request, env);
   if (!result) {
    if (req.url === '/api/settings') result = await handleGetSettings(env);
    else if (req.url === '/api/servers') result = Response.json({servers:[]});
    else if (req.url === '/api/server-groups') result = Response.json({groups:[]});
    else result = Response.json({}, {status:404});
   }
  }
  res.writeHead(result.status, Object.fromEntries(result.headers)); res.end(await result.text());
 } catch (e) { res.statusCode = 500; res.end(String(e)); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://localhost:${server.address().port}`;
let browser;
try {
 browser = await chromium.launch({headless:true, executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH});
 const context = await browser.newContext();
 await context.addCookies([{name:'besh_session', value:session.token, url:origin}]);
 const page = await context.newPage();
 const cdp = await context.newCDPSession(page);
 await cdp.send('WebAuthn.enable');
 const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol:'ctap2', transport:'usb', hasResidentKey:true, hasUserVerification:true, isUserVerified:true, automaticPresenceSimulation:true } });
 await page.goto(origin);
 const result = await page.evaluate(async ({password}) => {
  const post = async (path, body) => {
   const r = await fetch('/api/auth/security/'+path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
   const data = await r.json(); if (!r.ok) throw Error(JSON.stringify(data)); return data;
  };
  const passwordStep = async () => {
   const r = await fetch('/api/auth/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password})});
   const data = await r.json(); if (data.authenticated || !data.stageToken) throw Error('Password alone authenticated with a registered passkey'); return data;
  };
  const bytes = value => Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));
  const reg = await post('register/options', {password});
  const options = reg.options;
  options.challenge=bytes(options.challenge);options.user.id=bytes(options.user.id);
  options.excludeCredentials=options.excludeCredentials.map(k=>({...k,id:bytes(k.id)}));
  const credential = await navigator.credentials.create({publicKey: options});
  await post('register/verify',{challengeId:reg.challengeId,response:credential.toJSON(),name:'Virtual security key'});
  const authenticate = async () => {
   const step = await passwordStep();
   const bypass = await fetch('/api/auth/security/login/verify', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({stageToken:step.stageToken})});
   if (bypass.status !== 401) throw Error('Missing TOTP must not bypass passkey');
   const login = await post('passkey/options',{stageToken:step.stageToken});
   login.options.challenge=bytes(login.options.challenge);login.options.allowCredentials=login.options.allowCredentials.map(key=>({...key,id:bytes(key.id)}));
   const assertion = await navigator.credentials.get({publicKey:login.options});
   const body = {challengeId:login.challengeId,response:assertion.toJSON(),stageToken:step.stageToken};
   await post('passkey/verify',body);
   const replay=await fetch('/api/auth/security/passkey/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
   return replay.status;
  };
  const replayStatus=await authenticate();
  await authenticate(); // Stored signature counter must support the next assertion.
  const tamperedStep = await passwordStep();
  const tamperedOptions = await post('passkey/options', {stageToken:tamperedStep.stageToken});
  tamperedOptions.options.challenge = bytes(tamperedOptions.options.challenge);
  tamperedOptions.options.allowCredentials = tamperedOptions.options.allowCredentials.map(key=>({...key,id:bytes(key.id)}));
  const signed = (await navigator.credentials.get({publicKey:tamperedOptions.options})).toJSON();
  signed.response.signature = 'AAAA';
  const invalidSignature = await fetch('/api/auth/security/passkey/verify', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challengeId:tamperedOptions.challengeId,response:signed,stageToken:tamperedStep.stageToken})});
  if (invalidSignature.status !== 401) throw Error('Tampered signature accepted');
  const status=await (await fetch('/api/auth/security/status')).json();
  const pendingStep=await passwordStep();
  const login=await post('passkey/options',{stageToken:pendingStep.stageToken});login.options.challenge=bytes(login.options.challenge);login.options.allowCredentials=login.options.allowCredentials.map(key=>({...key,id:bytes(key.id)}));
  await post('passkey/delete',{password,id:credential.id});
  const removed=await navigator.credentials.get({publicKey:login.options});
  const rejected=await fetch('/api/auth/security/passkey/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challengeId:login.challengeId,response:removed.toJSON(),stageToken:pendingStep.stageToken})});
  return {replayStatus, keys:status.passkeys.length, removedStatus:rejected.status};
 }, {password});
 assert.deepEqual(result,{replayStatus:401,keys:1,removedStatus:401});
 console.log('PASS: Chromium FIDO2 registration, discoverable passkey login, signature counters, assertion replay rejection, deleted key rejection');
 // Exercise the built React application against the same real authentication handlers.
 sql.exec('DELETE FROM auth_limits');
 await context.clearCookies();
 await page.goto(origin+'/ui');
 await page.getByLabel('账户', {exact:true}).fill('admin');
 assert.equal(await page.locator('#login-code').count(), 0, 'initial login screen must not show OTP');
 assert.equal(await page.getByRole('button', {name:'使用通行密钥 / 安全密钥登录',exact:true}).count(), 0);
 await page.getByLabel('密码', {exact:true}).fill(password);
 await page.getByRole('button', {name:'登录',exact:true}).click();
 await page.getByRole('button', {name:'设置',exact:true}).click();
 await page.getByRole('tab', {name:'账户',exact:true}).click();
 const setupButton = page.getByRole('button', {name:'设置验证器',exact:true});
 await setupButton.waitFor({state:'visible'});
 await page.waitForFunction(() => !Array.from(document.querySelectorAll('button')).find(b=>b.textContent==='设置验证器')?.disabled);
 assert.equal(await setupButton.isEnabled(), true, 'setup is clickable before entering current password');
 await setupButton.click();
 await page.getByText('请先输入当前密码，再执行此操作。', {exact:true}).waitFor();
 assert.equal(await page.getByLabel('当前密码（管理安全设置时验证）').evaluate(el=>el===document.activeElement), true);
 assert.equal(sql.prepare('SELECT totp FROM account_security').get().totp, null);
 // Add a key so the staged UI must prefer it over TOTP.
 await page.evaluate(async ({password}) => {
  const post = async (path,body) => {
   const r=await fetch('/api/auth/security/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
   const data=await r.json();if(!r.ok)throw Error(JSON.stringify(data));return data;
  };
  const bytes=v=>Uint8Array.from(atob(v.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
  const reg=await post('register/options',{password});
  reg.options.challenge=bytes(reg.options.challenge);reg.options.user.id=bytes(reg.options.user.id);
  reg.options.excludeCredentials=reg.options.excludeCredentials.map(k=>({...k,id:bytes(k.id)}));
  const key=await navigator.credentials.create({publicKey:reg.options});
  await post('register/verify',{challengeId:reg.challengeId,response:key.toJSON(),name:'UI test key'});
 }, {password});
 session.token=(await context.cookies(origin)).find(c=>c.name==='besh_session').value;
 const localCall=(path,body)=>handleAccountSecurity(new Request(origin+'/api/auth/security/'+path,{method:'POST',headers:{Cookie:'besh_session='+session.token},body:JSON.stringify(body)}),env,path);
 const setupUi=await (await localCall('totp/setup',{password})).json();
 const enabledUi=await localCall('totp/enable',{challengeId:setupUi.challengeId,code:await totp(setupUi.secret,Math.floor(Date.now()/30000))});
 assert.equal(enabledUi.status,200);
 const uiRecovery=await enabledUi.json();
 sql.exec('DELETE FROM auth_limits');
 await context.clearCookies();
 await page.goto(origin+'/ui');
 assert.equal(await page.locator('#login-code').count(),0);
 await page.getByLabel('账户', {exact:true}).fill('admin');
 await page.getByLabel('密码', {exact:true}).fill(password);
 await page.getByRole('button',{name:'登录',exact:true}).click();
 await page.locator('#login-code').waitFor();
 await page.getByRole('button',{name:'使用通行密钥验证',exact:true}).click();
 await page.getByRole('button',{name:'设置',exact:true}).waitFor();
 // A pending passkey request must never block authenticator input. must fall back to the authenticator step.
 await context.clearCookies();
 let releasePasskeyOptions;
 await page.route('**/api/auth/security/passkey/options',async route=>{
  await new Promise(resolve=>releasePasskeyOptions=resolve);
  await route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{message:'Delayed passkey request'}})}).catch(()=>{});
 });
 await page.goto(origin+'/ui');
 assert.equal(await page.locator('#login-code').count(),0);
 await page.getByLabel('账户', {exact:true}).fill('admin');
 await page.getByLabel('密码', {exact:true}).fill(password);
 await page.getByRole('button',{name:'登录',exact:true}).click();
 await page.locator('#login-code').waitFor();
 await page.getByRole('button',{name:'使用通行密钥验证',exact:true}).click();
 await page.getByRole('button',{name:'正在等待通行密钥，可直接使用验证码',exact:true}).waitFor();
 assert.equal(await page.locator('#login-code').isEnabled(),true,'pending passkey request must not disable code input');
 assert.equal(await page.locator('#password').count(),0, 'second step does not retain password field');
 await page.locator('#login-code').fill('invalid');
 await page.getByRole('button',{name:'验证并登录',exact:true}).click();
 await page.getByRole('alert').waitFor();
 assert.equal((await context.cookies(origin)).some(c=>c.name==='besh_session'),false, 'bad OTP does not create a session');
 await page.locator('#login-code').fill(uiRecovery.recoveryCodes[0]);
 await page.getByRole('button',{name:'验证并登录',exact:true}).click();
 await page.getByRole('button',{name:'设置',exact:true}).waitFor();
 releasePasskeyOptions();
 await page.unroute('**/api/auth/security/passkey/options');
 // Keep the actual WebAuthn ceremony pending, then complete with a code.
 await context.clearCookies();
 await cdp.send('WebAuthn.setAutomaticPresenceSimulation',{authenticatorId,enabled:false});
 await page.goto(origin+'/ui');
 await page.getByLabel('账户',{exact:true}).fill('admin');
 await page.getByLabel('密码',{exact:true}).fill(password);
 await page.getByRole('button',{name:'登录',exact:true}).click();
 await page.locator('#login-code').waitFor();
 const waitingForAuthenticator=page.waitForRequest('**/api/auth/security/passkey/options');
 await page.getByRole('button',{name:'使用通行密钥验证',exact:true}).click();
 await waitingForAuthenticator;
 await page.getByRole('button',{name:'正在等待通行密钥，可直接使用验证码',exact:true}).waitFor();
 await page.locator('#login-code').fill(uiRecovery.recoveryCodes[1]);
 assert.equal(await page.getByRole('button',{name:'验证并登录',exact:true}).isEnabled(),true);
 await page.getByRole('button',{name:'验证并登录',exact:true}).click();
 await page.getByRole('button',{name:'设置',exact:true}).waitFor();
 assert.equal(await page.getByRole('alert').count(),0,'cancelled passkey must not overwrite successful code sign-in');
 console.log('PASS: code input immediately available after password, explicit passkey succeeds, pending options and pending WebAuthn do not block code sign-in, late passkey errors cannot overwrite success');

} finally { await browser?.close(); await new Promise(resolve => server.close(resolve)); }
