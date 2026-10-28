import { SshConnection } from '@besh/ssh-core'
import { getServerSecret } from './server-store.ts'
import { openCredential } from './credentials.ts'
import { readCredentialKey } from './credential-key.ts'
import { resolvePublicTarget } from './target.ts'

import { checkGrant, type MachineAgent } from './mcp-store.ts'

// No user-provided command, shell fragments, paths or service names are accepted.
// Root-managed NixOS system profile plus standard Linux binary paths. Never inherit
// an account's writable PATH, and use `command` to bypass shell functions.
const SYSTEM_PATH = 'PATH=/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH; '
export const DIAGNOSTICS = {
  system: SYSTEM_PATH + 'command uname -sr && command uptime',
  disk: SYSTEM_PATH + 'command df -Pk',
  memory: SYSTEM_PATH + 'command free -k',
} as const
export type DiagnosticName = keyof typeof DIAGNOSTICS
export async function inspectServer(env: { DB: D1Database; CREDENTIAL_KEY: string }, agent: MachineAgent, serverId: string, tool: 'server_status' | 'diagnostic_run' | 'command_exec', diagnostic?: DiagnosticName, command?: { command: string; timeoutSeconds: number; maxOutputBytes: number }): Promise<unknown> {
  await checkGrant(env.DB, agent, serverId, tool)
  const stored = await getServerSecret(env.DB, serverId)
  if (!stored?.server.fingerprint) throw new Error('HOST_KEY_NOT_TRUSTED')
  const { addresses } = await resolvePublicTarget(stored.server.host, { resolve: async hostname => {
    const url = new URL('https://cloudflare-dns.com/dns-query')
    url.searchParams.set('name', hostname); url.searchParams.set('type', 'A')
    const response = await fetch(url, { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) })
    if (!response.ok) throw new Error('DNS_UNAVAILABLE')
    const answer = await response.json() as { Answer?: Array<{type:number;data:string}> }
    return (answer.Answer ?? []).filter(a => a.type === 1 || a.type === 28).map(a => a.data)
  } })
  await checkGrant(env.DB, agent, serverId, tool)
  const { CloudflareTransportFactory } = await import('../platform/tcp.ts')
  const connection = new SshConnection({ factory: new CloudflareTransportFactory(), host: addresses[0], port: stored.server.port, connectTimeoutMs: 8000, hostKeyPolicy: d => d.fingerprint === stored.server.fingerprint })
  let revoked = false, checking = false
  const interval = setInterval(() => {
    if (checking) return
    checking = true
    void checkGrant(env.DB, agent, serverId, tool).catch(() => { revoked = true; void connection.close() }).finally(() => { checking = false })
  }, 1000)
  const deadline = setTimeout(() => { void connection.close() }, tool === 'command_exec' ? 45000 : 25000)
  try {
    await connection.connect()
    await checkGrant(env.DB, agent, serverId, tool)
    if (tool === 'server_status') return { serverId, reachable: true, hostKeyVerified: true, authenticated: false }
    const key = readCredentialKey(env)
    if (!key || (!diagnostic && !command)) throw new Error('DIAGNOSTIC_UNAVAILABLE')
    const secret = await openCredential(key, stored.credential, { serverId, kind: stored.server.authMethod === 'publickey' ? 'privateKey' : 'password' })
    if (stored.server.authMethod === 'publickey') await connection.authenticateWithKey({ username: stored.server.username, privateKey: secret })
    else await connection.authenticate({ username: stored.server.username, password: secret })
    await checkGrant(env.DB, agent, serverId, tool)
    const output = await connection.runCommand(command ? command.command : DIAGNOSTICS[diagnostic!], { timeoutMs: command ? command.timeoutSeconds*1000 : 8000, maxOutputBytes: command ? command.maxOutputBytes : 8192 })
    await checkGrant(env.DB, agent, serverId, tool)
    if (revoked) throw new Error('ACCESS_DENIED')
    return { serverId, diagnostic, ...output }
  } finally { clearInterval(interval); clearTimeout(deadline); await connection.close().catch(() => {}) }
}
