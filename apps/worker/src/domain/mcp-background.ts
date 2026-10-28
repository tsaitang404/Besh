import { inspectServer } from './mcp-diagnostics.ts'
import type { MachineAgent } from './mcp-store.ts'

export type BackgroundTool = 'command_start' | 'command_poll' | 'command_cancel'
type Task = { id: string; agent_id: string; server_id: string; expires_at: number }
const quote = (s: string) => "'" + s.replaceAll("'", "'\\''") + "'"
const encode = (s: string) => btoa(String.fromCharCode(...new TextEncoder().encode(s)))
const root = (id: string) => `/tmp/besh-mcp-${id}`

// Generated shell only. Commands are encoded separately and never interpolated as shell source.
export function startScript(id: string, command: string, timeout: number): string {
  const worker = `cd ${quote(root(id))} || exit 1
printf '%s\\n' "$$" > pid
ulimit -f 16384
command timeout -s TERM -k 5 ${timeout} sh command > output 2>&1
rc=$?
printf '%s\\n' "$rc" > exit.tmp
mv exit.tmp exit
`
  return `umask 077
for bin in setsid nohup timeout base64; do command -v "$bin" >/dev/null || exit 70; done
mkdir ${quote(root(id))} || exit 71
cd ${quote(root(id))} || exit 71
printf '%s' ${quote(encode(command))} | base64 -d > command || exit 72
printf '%s' ${quote(encode(worker))} | base64 -d > worker || exit 72
: > output
nohup setsid sh ${quote(root(id)+'/worker')} </dev/null >/dev/null 2>&1 &
i=0; while [ ! -s pid ] && [ "$i" -lt 3 ]; do sleep 1; i=$((i+1)); done
[ -s pid ] || exit 73
printf 'started\\n'`
}
export function pollScript(id: string, offset: number, maxBytes: number, cancel = false): string {
  return `cd ${quote(root(id))} || exit 74
${cancel ? `if [ ! -f exit ] && [ ! -f cancelled ]; then
 if [ -f pid ]; then read -r pid < pid; case "$pid" in ''|*[!0-9]*) exit 75;; esac
 # Refuse to signal a recycled PID after a machine restart or crashed wrapper.
 command tr '\\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | command grep -F ${quote(root(id)+'/worker')} >/dev/null || exit 75
 touch cancelled
 kill -KILL "-$pid" 2>/dev/null || true
 fi
fi` : ''}
printf '\nBESH_TASK_V1\n'
if [ -f cancelled ]; then printf 'cancelled\\n-\\n'; elif [ -f exit ]; then printf 'completed\\n'; cat exit; elif [ -f pid ]; then read -r pid < pid; if kill -0 "$pid" 2>/dev/null; then printf 'running\\n-\\n'; else printf 'lost\\n-\\n'; fi; else printf 'lost\\n-\\n'; fi
wc -c < output
command dd if=output bs=1 skip=${offset} count=${maxBytes} 2>/dev/null | base64
`
}
export async function backgroundCommand(env: { DB: D1Database; CREDENTIAL_KEY: string }, agent: MachineAgent, serverId: string, tool: BackgroundTool, args: Record<string, unknown>, commandHash?: string) {
  let taskId: string
  if (tool === 'command_start') {
    taskId = crypto.randomUUID()
    const timeout = Number(args.timeoutSeconds ?? 3600)
    // Record admission before remote launch; a transport failure must never trigger an automatic duplicate launch.
    await env.DB.prepare('INSERT INTO mcp_background_tasks(id,agent_id,server_id,created_at,expires_at,command_hash) VALUES(?,?,?,?,?,?)')
      .bind(taskId, agent.id, serverId, Date.now(), Date.now()+7*86400000, commandHash!).run()
    try {
      const result = await inspectServer(env, agent, serverId, tool, undefined, { command: startScript(taskId, String(args.command), timeout), timeoutSeconds: 8, maxOutputBytes: 1024 }) as { exitCode: number | null }
      return { taskId, serverId, status: result.exitCode === 0 ? 'running' : 'start_unknown', launchExitCode: result.exitCode, timeoutSeconds: timeout, pollIntervalMs: 2000, retentionDays: 7 }
    } catch (e) {
      // Task ID lets callers reconcile an ambiguous launch instead of duplicating the command.
      if (e instanceof Error && e.message === 'ACCESS_DENIED') throw e
      return { taskId, serverId, status: 'start_unknown', pollIntervalMs: 2000 }
    }
  }
  taskId = String(args.taskId)
  const task = await env.DB.prepare('SELECT id,agent_id,server_id,expires_at FROM mcp_background_tasks WHERE id=? AND agent_id=? AND server_id=? AND expires_at>?')
    .bind(taskId, agent.id, serverId, Date.now()).first<Task>()
  if (!task) throw new Error('TASK_NOT_FOUND')
  const offset = Number(args.offset ?? 0), maxBytes = Number(args.maxOutputBytes ?? 16384)
  const result = await inspectServer(env, agent, serverId, tool, undefined, { command: pollScript(taskId, offset, maxBytes, tool === 'command_cancel'), timeoutSeconds: 8, maxOutputBytes: 100000 }) as { exitCode: number | null; stdout: string }
  if (result.exitCode !== 0) return { taskId, serverId, status: result.exitCode === 74 ? 'lost' : 'query_failed', exitCode: null }
  const marker = result.stdout.lastIndexOf('\nBESH_TASK_V1\n')
  if (marker < 0) throw new Error('INVALID_TASK_RESPONSE')
  const [status, exit, length, ...encoded] = result.stdout.slice(marker+'\nBESH_TASK_V1\n'.length).trim().split('\n')
  if (!['running','completed','cancelled','lost'].includes(status) || !/^\d+$/.test(length) || (exit !== '-' && !/^\d+$/.test(exit))) throw new Error('INVALID_TASK_RESPONSE')
  const binary = atob(encoded.join('').replaceAll(/\s/g, ''))
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0))
  return { taskId, serverId, status, exitCode: exit === '-' ? null : Number(exit), output: new TextDecoder().decode(bytes), outputBase64: btoa(binary), offset, nextOffset: offset+bytes.length, totalOutputBytes: Number(length), hasMore: Number(length)>offset+bytes.length, pollIntervalMs: 2000 }
}
