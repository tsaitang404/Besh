import type { ChatConfig } from "./ai-chat.ts"

export const WORKERS_AI_MODEL = "@cf/qwen/qwen3-30b-a3b-fp8"
export const WORKERS_AI_MAX_OUTPUT = 2048
export type WorkersAiBinding = {
  run(model: string, input: Record<string, unknown>, options?: { returnRawResponse: true }): Promise<unknown>
}
export type WorkersAiEnv = { AI?: WorkersAiBinding; DB: D1Database }

/** Best-effort request statistics; never a gate on model access. */
export async function recordWorkersAiRequest(db: D1Database, now = Date.now()): Promise<void> {
  const day = new Date(now).toISOString().slice(0, 10)
  await db.prepare(
    `INSERT INTO workers_ai_budget (day, requests) VALUES (?, 1)
     ON CONFLICT(day) DO UPDATE SET requests = requests + 1 RETURNING requests`
  ).bind(day).first<{ requests: number }>()
}

export async function workersAiStatus(env: WorkersAiEnv) {
  if (!env.AI) return null
  const day = new Date().toISOString().slice(0, 10)
  const row = await env.DB.prepare("SELECT requests FROM workers_ai_budget WHERE day = ?")
    .bind(day).first<{ requests: number }>()
  return { model: WORKERS_AI_MODEL, requestsUsed: row?.requests ?? 0 }
}

/** Keep the existing OpenAI/SSE parser, cancellation and manual approval policy. */
export function workersAiProvider(env: WorkersAiEnv): ChatConfig | null {
  const binding = env.AI
  if (!binding) return null
  return {
    baseUrl: "workers-ai://native", apiKey: "", model: WORKERS_AI_MODEL,
    contextWindow: 32768, maxOutput: WORKERS_AI_MAX_OUTPUT,
    request: async (body, signal) => {
      signal.throwIfAborted()
      await recordWorkersAiRequest(env.DB).catch(() => undefined)
      signal.throwIfAborted()
      const { model: _model, reasoning_effort: _effort, ...input } = body
      const messages = input.messages as Array<{ content?: unknown }> | undefined
      if (messages?.some(message => Array.isArray(message.content) && message.content.some(part => part.type === "image_url"))) {
        throw new Error("内置 Workers AI 模型仅支持文本，请切换支持图片的自定义模型。")
      }
      let output = await binding.run(WORKERS_AI_MODEL, {
        ...input, max_tokens: WORKERS_AI_MAX_OUTPUT,
      }, { returnRawResponse: true })
      if (output instanceof Response) {
        if (!output.ok) return output
        if ((output.headers.get("content-type") ?? "").includes("text/event-stream")) output = output.body
        else {
          const parsed = await output.json() as Record<string, unknown>
          output = parsed.result ?? parsed
        }
      }
      if (signal.aborted) {
        if (output instanceof ReadableStream) await output.cancel().catch(() => undefined)
        signal.throwIfAborted()
      }
      if (output instanceof ReadableStream) {
        const reader = output.getReader()
        const abort = () => { void reader.cancel().catch(() => undefined) }
        signal.addEventListener("abort", abort, { once: true })
        const cleanup = () => signal.removeEventListener("abort", abort)
        const stream = new ReadableStream({
          async pull(controller) {
            try {
              const chunk = await reader.read()
              if (chunk.done) { cleanup(); controller.close() }
              else controller.enqueue(chunk.value)
            } catch (error) { cleanup(); controller.error(error) }
          },
          async cancel(reason) { cleanup(); await reader.cancel(reason) },
        })
        return new Response(stream, { headers: { "content-type": "text/event-stream" } })
      }
      return Response.json(output)
    },
  }
}
