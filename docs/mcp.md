# Machine MCP access (phase 1)

`POST /mcp` implements stateless Streamable HTTP JSON-RPC: initialize, initialized notification, ping, tools/list, tools/call. No browser cookie, administrator password, OTP or passkey is accepted on this endpoint. GET returns 405; no persistent MCP session can retain revoked permissions.

## Authentication and scope

Protect `ssh.sadd.ing/mcp` with a separate Cloudflare Access self-hosted application using Service Auth policies. Configure `MCP_ACCESS_ISSUER` and `MCP_ACCESS_AUD` for that application. Besh verifies RS256 signatures against the configured team's JWKS and validates issuer, audience, expiry and machine common_name. Header presence alone, human identities and caller-supplied forwarding headers do not authorize operations. `MCP_ENABLED=false` disables MCP independently of human login. Workers.dev and preview URLs remain disabled.

Bind the Access service token's client ID (`*.access`) to one `mcp_agents` record. Records require explicit enablement, an expiry and per-server/tool grants. Unknown machines and unknown servers fail closed. Every tool call checks D1 authorization again; agent changes increment its version. Grant or identity changes invalidate operations already running; SSH tasks poll every second and suppress results after revocation. Commands already executed cannot be undone.

## Tools

- `servers_list`: only explicitly granted inventory, limited to 100 records, no credentials or usernames.
- `server_status(serverId)`: SSH handshake and pinned host-key verification; does not authenticate or trust a new key.
- `diagnostic_run(serverId, diagnostic)`: fixed Linux diagnostics `system`, `disk`, `memory`. No caller command, paths or shell interpolation. Stored SSH credentials remain internal. Existing trusted host key required. Maximum output 8 KiB, command timeout 8 seconds, connection deadline 25 seconds.

Per identity concurrency is 2; global concurrency is 8, enforced with atomic D1 admission leases. Caller cancellation does not imply command cancellation; operations are bounded by these deadlines. Output is untrusted host data. Phase 1 intentionally has no terminal, arbitrary exec, file operations or credential-management tools.

## Portal

Register the origin as a bearer-auth MCP server with custom headers containing a dedicated origin Access service token. Link it to the existing Portal with `on_behalf=false`. Add matching Service Auth policies to the Portal and linked MCP logical Access application for caller tokens; the origin Access application authorizes only origin credentials and specifically approved direct callers.

**Shared upstream identity:** the Portal uses its configured upstream credential for all callers. Besh audits this as a shared `Besh Portal` principal. It does not claim individual caller attribution from arbitrary headers. Use separate upstream registrations/credentials and grant sets when callers need different Besh scopes. Portal Access logs retain caller-side identity separately. Direct callers can each use distinct service tokens bound to their own Besh agent records.

## Administration and revocation

Existing human administrator session and same-origin rules protect these APIs:

- `GET /api/mcp/agents`: identities and grants (no token secrets).
- `POST /api/mcp/agents`: `{name, commonName, enabled, expiresAt, grants:[{serverId,tool}]}`.
- `PUT /api/mcp/agents/:id`: full replacement of that configuration plus current `version`; optimistic concurrency prevents stale overwrites. Disabling uses `enabled:false`; removing grants revokes their scope.
- `GET /api/mcp/audit`: latest 100 events. Only metadata (identity/tool/server/diagnostic/outcome/duration) is stored; never tokens, credentials or command output. Records retained for 90 days by the scheduled sweep.

The first release provides administration APIs; there is no machine-permissions settings panel yet. Operators with D1 access can provision/revoke records during deployment. Always increment `version` when editing grants directly. Do not distribute Portal origin secrets to agents; keep them in Portal credential storage. Token material on the operator host belongs in permission-600 service configuration, outside the repository.

To roll back, disable MCP or disable agent records, then remove the Besh Portal mapping while preserving all other mappings. The additive `0004_mcp.sql` migration does not alter human accounts or existing SSH inventory. Do not delete existing audit evidence during rollback.

## Verification

`node tests/mcp-security.mjs` tests JWT validation, permissions, revocation, malformed/extra arguments, host-key pinning and audit redaction using synthetic identities. Production acceptance additionally requires calls through Access and the Portal: allowed inventory/diagnostic, denied other server, disable agent, reuse the existing client session and observe denial, restore only the intended final grant set.

## Production acceptance — 2026-10-28

Deployed to `ssh.sadd.ing/mcp` and registered as `besh` in the existing `mcp.sadd.ing` Portal, preserving SDE, Trilium and Vaultwarden. Portal upstream reports `ready` / `connected` with all three tools. Separate 30-day service identities were created for Portal-origin access and acceptance/direct access, with credentials stored only in Portal and permission-600 operator configuration on soul.

The initial grant set covers **minius only**. Both direct Access and a machine Portal session successfully listed only minius, verified its pinned SSH host key and ran a fixed diagnostic. A request for soul was denied. On the same existing Portal session, disabling `besh-portal` caused an upstream 403; restoring it recovered inventory. Removing only minius's `server_status` grant then returned `ACCESS_DENIED`; restoring the grant recovered the live SSH probe. Intended permissions were restored after testing. Existing human authentication/FIDO2/Turnstile tests also passed.

The Portal path intentionally reports the shared `besh-portal` identity; individual Portal clients do not gain independent downstream identity from this first release. Existing OAuth client sessions may need their server selection refreshed to add Besh.

### NixOS diagnostic correction

The first acceptance probe checked tool transport success without checking the remote exit code. A current-chat probe found minius returned exit code 127 because `/usr/bin/uname` and `/usr/bin/uptime` do not exist on NixOS. Diagnostics now use a fixed root-managed system PATH including the NixOS system profile. Nonzero, missing or null exit codes return MCP `isError:true` and audit outcome `DIAGNOSTIC_FAILED`, retaining bounded output for troubleshooting. `system` uses `&&` so an earlier failure cannot be masked by a later command.

## Direct command control

At the owner's request, command access uses the single `command_exec(serverId, command, timeoutSeconds?, maxOutputBytes?)` tool. No proposal, human approval step or separate limited SSH account is involved. It uses that server's existing stored SSH account, including whatever sudo privileges the account already has. Production grants this tool only to the `besh-portal` principal on minius; other hosts remain inaccessible.

CF Access, Besh per-server grants, pinned host keys, credential isolation, concurrent-operation limits and auditing still apply. Commands are passed intentionally as shell commands; this is full account control, not a command allowlist or sandbox. Audit records contain only the SHA-256 command hash, identity, target, result and timing, not command text/output. Default command timeout is 15 seconds, maximum 30 seconds, output up to 64 KiB. Nonzero or missing exit codes return `isError:true`. Long-running background processes and completed writes are not rolled back by a connection timeout or permission revocation.

The previously deployed approval-runner schema remains as additive migration history, but its UI, tools and runtime have been removed. No approval jobs were started. The temporary dedicated account/key and seed secret are retired separately.
