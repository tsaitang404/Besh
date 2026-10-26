import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { totp, matchTotp } from '../apps/worker/src/domain/totp.ts';
import { createAdmin, getAdmin, insertSession, updateAdminPassword } from '../apps/worker/src/domain/admin-store.ts';
import { hashPassword, createSessionToken, hashSessionToken } from '../apps/worker/src/domain/auth.ts';
import { handleLogin } from '../apps/worker/src/http/auth.ts';
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
response = await login(); assert.equal(response.status, 401); assert.equal(response.headers.get('Set-Cookie'), null);
response = await login({code: recoveryCodes[1]}); assert.equal(response.status, 200);
session.token = response.headers.get('Set-Cookie').split(';')[0].split('=')[1];
assert.equal((await login({code: recoveryCodes[1]})).status, 401);
// One-time challenge and session binding, with registration cancellation.
response = await call('register/options', { password, code: recoveryCodes[2] }); assert.equal(response.status, 200);
const reg = await response.json();
assert.equal((await call('register/verify', { challengeId: reg.challengeId, response: {} })).status, 400);
assert.equal((await call('register/verify', { challengeId: reg.challengeId, response: {} })).status, 401);
response = await call('passkey/options', {}); const auth = await response.json();
sql.prepare('UPDATE auth_challenges SET expires_at = 0 WHERE id = ?').run(auth.challengeId);
assert.equal((await call('passkey/verify', {challengeId: auth.challengeId, response: {id: 'unknown'}})).status, 401);
const oldAdmin = await getAdmin(db);
response = await call('totp/disable', { password, code: recoveryCodes[3] }); assert.equal(response.status, 200);
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
  let body = ''; for await (const chunk of req) body += chunk;
  const request = new Request(origin + req.url, { method: req.method, headers: req.headers, ...(req.method === 'POST' ? {body} : {}) });
  const path = req.url.slice('/api/auth/security/'.length);
  const result = await handleAccountSecurity(request, env, path);
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
 await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol:'ctap2', transport:'usb', hasResidentKey:true, hasUserVerification:true, isUserVerified:true, automaticPresenceSimulation:true } });
 await page.goto(origin);
 const result = await page.evaluate(async ({password}) => {
  const post = async (path, body) => {
   const r = await fetch('/api/auth/security/'+path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
   const data = await r.json(); if (!r.ok) throw Error(JSON.stringify(data)); return data;
  };
  const bytes = value => Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));
  const reg = await post('register/options', {password});
  const options = reg.options;
  options.challenge=bytes(options.challenge);options.user.id=bytes(options.user.id);
  options.excludeCredentials=options.excludeCredentials.map(k=>({...k,id:bytes(k.id)}));
  const credential = await navigator.credentials.create({publicKey: options});
  await post('register/verify',{challengeId:reg.challengeId,response:credential.toJSON(),name:'Virtual security key'});
  const authenticate = async () => {
   const login = await post('passkey/options',{});
   login.options.challenge=bytes(login.options.challenge);
   const assertion = await navigator.credentials.get({publicKey:login.options});
   const body = {challengeId:login.challengeId,response:assertion.toJSON()};
   await post('passkey/verify',body);
   const replay=await fetch('/api/auth/security/passkey/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
   return replay.status;
  };
  const replayStatus=await authenticate();
  await authenticate(); // Stored signature counter must support the next assertion.
  const tamperedOptions = await post('passkey/options', {});
  tamperedOptions.options.challenge = bytes(tamperedOptions.options.challenge);
  const signed = (await navigator.credentials.get({publicKey:tamperedOptions.options})).toJSON();
  signed.response.signature = 'AAAA';
  const invalidSignature = await fetch('/api/auth/security/passkey/verify', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challengeId:tamperedOptions.challengeId,response:signed})});
  if (invalidSignature.status !== 401) throw Error('Tampered signature accepted');
  const status=await (await fetch('/api/auth/security/status')).json();
  await post('passkey/delete',{password,id:credential.id});
  const login=await post('passkey/options',{});login.options.challenge=bytes(login.options.challenge);
  const removed=await navigator.credentials.get({publicKey:login.options});
  const rejected=await fetch('/api/auth/security/passkey/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challengeId:login.challengeId,response:removed.toJSON()})});
  return {replayStatus, keys:status.passkeys.length, removedStatus:rejected.status};
 }, {password});
 assert.deepEqual(result,{replayStatus:401,keys:1,removedStatus:401});
 console.log('PASS: Chromium FIDO2 registration, discoverable passkey login, signature counters, assertion replay rejection, deleted key rejection');
} finally { await browser?.close(); await new Promise(resolve => server.close(resolve)); }
