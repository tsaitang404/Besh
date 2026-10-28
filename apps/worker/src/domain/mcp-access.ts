import { createRemoteJWKSet, jwtVerify } from 'jose'

export type McpAccessEnv = { MCP_ENABLED?: string; MCP_ACCESS_ISSUER?: string; MCP_ACCESS_AUD?: string }
const keysets = new Map<string, ReturnType<typeof createRemoteJWKSet>>()
/** Only a cryptographically verified Access service-token principal is accepted. */
export async function verifyMachine(request: Request, env: McpAccessEnv): Promise<string | null> {
  if (env.MCP_ENABLED !== 'true' || !env.MCP_ACCESS_ISSUER || !env.MCP_ACCESS_AUD) return null
  const issuer = env.MCP_ACCESS_ISSUER
  if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(issuer)) return null
  const token = request.headers.get('Cf-Access-Jwt-Assertion')
  if (!token || token.length > 16384) return null
  try {
    let keys = keysets.get(issuer)
    if (!keys) { keys = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`), { timeoutDuration: 5000 }); keysets.set(issuer, keys) }
    const { payload } = await jwtVerify(token, keys, { issuer, audience: env.MCP_ACCESS_AUD, algorithms: ['RS256'], requiredClaims: ['exp', 'iat'] })
    if (payload.type !== 'app' || typeof payload.common_name !== 'string' || !payload.common_name.endsWith('.access')) return null
    return payload.common_name
  } catch { return null }
}
