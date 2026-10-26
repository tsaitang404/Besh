import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server"
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server"
import { getAdmin, insertSession } from "../domain/admin-store.ts"
import type { AdminRow } from "../domain/admin-store.ts"
import { buildSessionCookie, createSessionToken, hashSessionToken, readCookie, verifyPassword } from "../domain/auth.ts"
import { toBytes, base64ToBytes, bytesToBase64, bytesToBase64Url, randomBytes } from "../domain/bytes.ts"
import { openCredential, sealCredential } from "../domain/credentials.ts"
import { readCredentialKey } from "../domain/credential-key.ts"
import { matchTotp, newTotpSecret } from "../domain/totp.ts"
import { jsonError, requireAdmin } from "./auth.ts"
import type { AuthEnv } from "./auth.ts"
import { json } from "./response.ts"

type Security = { totp: string | null; last_step: number }
type Passkey = { id: string; name: string; public_key: string; counter: number; transports: string; created_at: number }
type Challenge = { payload: string; version: number }
const aad = { serverId: "admin", kind: "totpSecret" as const }
export async function securityState(db: D1Database): Promise<Security> {
  return (await db.prepare("SELECT totp, last_step FROM account_security WHERE id = 1").first<Security>())!
}
// Persistent fixed windows shared by login, assertions and security reauthentication.
// Global limit also bounds attackers rotating source IP addresses.
export async function authRateLimit(request: Request, db: D1Database): Promise<boolean> {
  const window = Math.floor(Date.now() / 300000)
  const ip = request.headers.get("CF-Connecting-IP") ?? "local"
  await db.prepare("DELETE FROM auth_limits WHERE bucket NOT LIKE ?").bind(`${window}:%`).run()
  for (const [suffix, limit] of [[ip, 30], ["global", 150]] as const) {
    const row = await db.prepare("INSERT INTO auth_limits(bucket, attempts) VALUES (?, 1) ON CONFLICT(bucket) DO UPDATE SET attempts = attempts + 1 RETURNING attempts")
      .bind(`${window}:${suffix}`).first<{ attempts: number }>()
    if (!row || row.attempts > limit) return false
  }
  return true
}
export async function verifySecondFactor(env: AuthEnv, code: unknown): Promise<boolean> {
  const state = await securityState(env.DB)
  if (!state.totp) return true
  if (typeof code !== "string") return false
  const key = readCredentialKey(env)
  if (!key) return false
  const secret = await openCredential(key, JSON.parse(state.totp), aad)
  const step = await matchTotp(secret, code.trim())
  if (step !== null) {
    const result = await env.DB.prepare("UPDATE account_security SET last_step = ? WHERE id = 1 AND totp = ? AND last_step < ?")
      .bind(step, state.totp, step).run()
    return result.meta.changes === 1
  }
  const used = await env.DB.prepare("DELETE FROM recovery_codes WHERE hash = ? RETURNING hash").bind(await hashSessionToken(code.trim().toLowerCase())).first()
  return !!used
}
export async function issueSecuritySession(request: Request, env: AuthEnv, admin: AdminRow): Promise<Response> {
  const now = Date.now(), session = await createSessionToken(now)
  if (!await insertSession(env.DB, { hash: session.hash, createdAt: now, expiresAt: session.expiresAt }, admin)) return jsonError("AUTH_REQUIRED", "Authentication changed; sign in again", 401)
  return json({ authenticated: true }, 200, { "Set-Cookie": buildSessionCookie(session.token, { secure: new URL(request.url).protocol === "https:" }) })
}
/** Password proof is short-lived, origin-bound and cannot authorize normal API access. */
export async function beginLoginStep(request: Request, env: AuthEnv, admin: AdminRow): Promise<Response | null> {
  const state = await securityState(env.DB)
  const passkey = await env.DB.prepare("SELECT id FROM passkeys LIMIT 1").first()
  if (!state.totp && !passkey) return null
  const stageToken = bytesToBase64Url(randomBytes(32))
  const now = Date.now()
  await env.DB.prepare("DELETE FROM auth_challenges WHERE expires_at <= ?").bind(now).run()
  await env.DB.prepare("INSERT INTO auth_challenges VALUES (?, ?, ?, ?, ?, ?)")
    .bind(await hashSessionToken(stageToken), "login-step", JSON.stringify({ origin: new URL(request.url).origin }), "", admin.securityVersion, now + 300000).run()
  return json({ authenticated: false, secondFactorRequired: true, stageToken, methods: { passkey: !!passkey, totp: !!state.totp } })
}
async function readLoginStep(request: Request, env: AuthEnv, admin: AdminRow, token: unknown): Promise<string | null> {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null
  const hash = await hashSessionToken(token)
  const row = await env.DB.prepare("SELECT payload, version FROM auth_challenges WHERE id = ? AND purpose = 'login-step' AND expires_at > ?")
    .bind(hash, Date.now()).first<Challenge>()
  if (!row || row.version !== admin.securityVersion || JSON.parse(row.payload).origin !== new URL(request.url).origin) return null
  return hash
}
async function consumeLoginStep(request: Request, env: AuthEnv, admin: AdminRow, hash: string): Promise<boolean> {
  const row = await takeChallenge(env, hash, "login-step", "")
  return !!row && row.version === admin.securityVersion && JSON.parse(row.payload).origin === new URL(request.url).origin
}
async function saveChallenge(env: AuthEnv, purpose: string, payload: unknown, sessionHash: string, version: number) {
  const id = bytesToBase64Url(randomBytes(32)), now = Date.now()
  await env.DB.prepare("DELETE FROM auth_challenges WHERE expires_at <= ?").bind(now).run()
  await env.DB.prepare("INSERT INTO auth_challenges VALUES (?, ?, ?, ?, ?, ?)").bind(id, purpose, JSON.stringify(payload), sessionHash, version, now + 300000).run()
  return id
}
async function takeChallenge(env: AuthEnv, id: unknown, purpose: string, sessionHash: string): Promise<Challenge | null> {
  if (typeof id !== "string") return null
  return env.DB.prepare("DELETE FROM auth_challenges WHERE id = ? AND purpose = ? AND session_hash = ? AND expires_at > ? RETURNING payload, version")
    .bind(id, purpose, sessionHash, Date.now()).first<Challenge>()
}
// Security changes and revocation commit atomically and use compare-and-swap.
async function changeSecurity(request: Request, env: AuthEnv, admin: AdminRow, statements: D1PreparedStatement[]): Promise<Response> {
  const next = admin.securityVersion + 1
  let results: D1Result[]
  try {
    results = await env.DB.batch([
      // A stale mutation fails its CHECK and rolls back the entire batch.
      env.DB.prepare("UPDATE admin SET security_version = CASE WHEN security_version = ? AND password_hash = ? THEN ? ELSE -1 END WHERE id = 1")
        .bind(admin.securityVersion, admin.hash, next),
      ...statements,
      env.DB.prepare("DELETE FROM admin_sessions"),
      env.DB.prepare("DELETE FROM auth_challenges"),
    ])
  } catch (error) {
    const current = await getAdmin(env.DB)
    if (!current || current.securityVersion !== admin.securityVersion || current.hash !== admin.hash) {
      return jsonError("AUTH_REQUIRED", "Authentication changed; sign in again", 401)
    }
    throw error
  }
  if (!results[0].success) return jsonError("AUTH_REQUIRED", "Authentication changed", 401)
  return issueSecuritySession(request, env, { ...admin, securityVersion: next })
}
export async function handleAccountSecurity(request: Request, env: AuthEnv, path: string): Promise<Response> {
  const publicRoute = path === "passkey/options" || path === "passkey/verify" || path === "login/verify"
  if (!publicRoute) { const denied = await requireAdmin(request, env); if (denied) return denied }
  if (path === "status" && request.method === "GET") {
    const state = await securityState(env.DB)
    const keys = await env.DB.prepare("SELECT id, name, created_at FROM passkeys ORDER BY created_at").all()
    const count = await env.DB.prepare("SELECT count(*) AS count FROM recovery_codes").first<{ count: number }>()
    return json({ totpEnabled: !!state.totp, passkeys: keys.results, recoveryCodesRemaining: count?.count ?? 0 })
  }
  if (request.method !== "POST") return jsonError("INVALID_REQUEST", "Method not allowed", 405)
  if (!await authRateLimit(request, env.DB)) return jsonError("FORBIDDEN", "Too many attempts; try again in five minutes", 429)
  let body: Record<string, unknown>
  try { const parsed = await request.json(); if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw Error(); body = parsed as Record<string, unknown> }
  catch { return jsonError("INVALID_REQUEST", "Expected JSON object", 400) }
  const admin = await getAdmin(env.DB)
  if (!admin) return jsonError("AUTH_REQUIRED", "Invalid credentials", 401)
  const url = new URL(request.url), rpID = url.hostname, origin = url.origin
  if (url.protocol !== "https:" && rpID !== "localhost" && rpID !== "127.0.0.1") return jsonError("INVALID_REQUEST", "HTTPS is required", 400)
  const sessionHash = publicRoute ? "" : await hashSessionToken(readCookie(request.headers.get("Cookie"))!)
  const stageHash = publicRoute ? await readLoginStep(request, env, admin, body.stageToken) : null
  if (publicRoute && !stageHash) return jsonError("AUTH_REQUIRED", "Password verification expired; sign in again", 401)
  const keys = await env.DB.prepare("SELECT * FROM passkeys").all<Passkey>()
  if (path === "login/verify") {
    if (!(await securityState(env.DB)).totp || !await verifySecondFactor(env, body.code)) {
      return jsonError("AUTH_REQUIRED", "Invalid authenticator or recovery code", 401)
    }
    if (!await consumeLoginStep(request, env, admin, stageHash!)) return jsonError("AUTH_REQUIRED", "Password verification expired; sign in again", 401)
    return issueSecuritySession(request, env, admin)
  }
  if (path === "passkey/options") {
    if (keys.results.length === 0) return jsonError("INVALID_REQUEST", "No passkey is registered", 400)
    const options = await generateAuthenticationOptions({ rpID, userVerification: "required", allowCredentials: keys.results.map(key => ({ id: key.id, transports: JSON.parse(key.transports) })) })
    const challengeId = await saveChallenge(env, "login", options.challenge, stageHash!, admin.securityVersion)
    return json({ options, challengeId })
  }
  if (path === "passkey/verify") {
    const challenge = await takeChallenge(env, body.challengeId, "login", stageHash!)
    const response = body.response as AuthenticationResponseJSON | undefined
    const stored = keys.results.find(key => key.id === response?.id)
    if (!challenge || challenge.version !== admin.securityVersion || !stored || !response) return jsonError("AUTH_REQUIRED", "Invalid passkey", 401)
    try {
      const result = await verifyAuthenticationResponse({ response, expectedChallenge: JSON.parse(challenge.payload), expectedOrigin: origin, expectedRPID: rpID,
        credential: { id: stored.id, publicKey: toBytes(base64ToBytes(stored.public_key)), counter: stored.counter }, requireUserVerification: true })
      if (!result.verified) throw Error()
      const update = await env.DB.prepare("UPDATE passkeys SET counter = ? WHERE id = ? AND counter = ?").bind(result.authenticationInfo.newCounter, stored.id, stored.counter).run()
      if (update.meta.changes !== 1) throw Error()
      if (!await consumeLoginStep(request, env, admin, stageHash!)) return jsonError("AUTH_REQUIRED", "Password verification expired; sign in again", 401)
      return issueSecuritySession(request, env, admin)
    } catch { return jsonError("AUTH_REQUIRED", "Invalid passkey", 401) }
  }
  // Completion is bound to the authenticated session and the reauthentication at start.
  if (path === "register/verify" || path === "totp/enable") {
    const purpose = path === "register/verify" ? "register" : "totp"
    const challenge = await takeChallenge(env, body.challengeId, purpose, sessionHash)
    if (!challenge || challenge.version !== admin.securityVersion) return jsonError("AUTH_REQUIRED", "Setup expired; start again", 401)
    if (purpose === "register") {
      try {
        const result = await verifyRegistrationResponse({ response: body.response as RegistrationResponseJSON, expectedChallenge: JSON.parse(challenge.payload), expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true })
        if (!result.verified || !result.registrationInfo) throw Error()
        const credential = result.registrationInfo.credential
        const name = typeof body.name === "string" ? body.name.trim().slice(0, 64) : "Passkey"
        return await changeSecurity(request, env, admin, [env.DB.prepare("INSERT INTO passkeys VALUES (?, ?, ?, ?, ?, ?)").bind(credential.id, name || "Passkey", bytesToBase64(credential.publicKey), credential.counter, JSON.stringify(credential.transports ?? []), Date.now())])
      } catch { return jsonError("INVALID_REQUEST", "Passkey registration failed; start again", 400) }
    }
    const key = readCredentialKey(env)
    if (!key) return jsonError("INTERNAL", "Credential key is not configured", 500)
    const sealed = JSON.parse(challenge.payload)
    const secret = await openCredential(key, sealed, aad)
    const step = await matchTotp(secret, typeof body.code === "string" ? body.code : "")
    if (step === null) return jsonError("INVALID_REQUEST", "Invalid verification code; start setup again", 400)
    const codes = Array.from({ length: 10 }, () => bytesToBase64Url(randomBytes(12)).toLowerCase())
    const hashes = await Promise.all(codes.map(code => hashSessionToken(code)))
    const response = await changeSecurity(request, env, admin, [
      env.DB.prepare("UPDATE account_security SET totp = ?, last_step = ? WHERE id = 1").bind(JSON.stringify(sealed), step),
      env.DB.prepare("DELETE FROM recovery_codes"),
      ...hashes.map(hash => env.DB.prepare("INSERT INTO recovery_codes VALUES (?)").bind(hash)),
    ])
    if (response.status !== 200) return response
    return json({ recoveryCodes: codes }, 200, { "Set-Cookie": response.headers.get("Set-Cookie")! })
  }
  if (typeof body.password !== "string" || !await verifyPassword(body.password, admin) || !await verifySecondFactor(env, body.code)) return jsonError("AUTH_REQUIRED", "Invalid password or verification code", 401)
  if (path === "register/options") {
    if (keys.results.length >= 20) return jsonError("INVALID_REQUEST", "At most 20 passkeys are allowed", 400)
    const options = await generateRegistrationOptions({ rpName: "Besh", rpID, userName: admin.username,
      userID: toBytes(new TextEncoder().encode(`besh-admin-${admin.createdAt}`)),
      excludeCredentials: keys.results.map(key => ({ id: key.id })),
      authenticatorSelection: { residentKey: "required", userVerification: "required" }, supportedAlgorithmIDs: [-7, -257] })
    return json({ options, challengeId: await saveChallenge(env, "register", options.challenge, sessionHash, admin.securityVersion) })
  }
  if (path === "passkey/delete") return changeSecurity(request, env, admin, [env.DB.prepare("DELETE FROM passkeys WHERE id = ?").bind(typeof body.id === "string" ? body.id : "")])
  if (path === "totp/setup") {
    if ((await securityState(env.DB)).totp) return jsonError("INVALID_REQUEST", "Two-step verification is already enabled", 400)
    const key = readCredentialKey(env)
    if (!key) return jsonError("INTERNAL", "Credential key is not configured", 500)
    const secret = newTotpSecret(), sealed = await sealCredential(key, secret, { ...aad, keyVersion: 1 })
    return json({ secret, uri: `otpauth://totp/${encodeURIComponent(`Besh:${admin.username}`)}?secret=${secret}&issuer=Besh&algorithm=SHA1&digits=6&period=30`, challengeId: await saveChallenge(env, "totp", sealed, sessionHash, admin.securityVersion) })
  }
  if (path === "totp/disable") return changeSecurity(request, env, admin, [env.DB.prepare("UPDATE account_security SET totp = NULL, last_step = -1 WHERE id = 1"), env.DB.prepare("DELETE FROM recovery_codes")])
  return jsonError("NOT_FOUND", "Unknown security endpoint", 404)
}
