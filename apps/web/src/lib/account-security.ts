import { startAuthentication, startRegistration, WebAuthnAbortService } from "@simplewebauthn/browser"
import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser"
export type LoginStep = { authenticated: false; secondFactorRequired: true; stageToken: string; methods: { passkey: boolean; totp: boolean } }
export type LoginResult = { authenticated: true } | LoginStep
export type SecurityStatus = { totpEnabled: boolean; passkeys: { id: string; name: string; created_at: number }[]; recoveryCodesRemaining: number }
export async function securityRequest<T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`/api/auth/security/${path}`, {
    signal,
    method: body === undefined ? "GET" : "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
  const result = await response.json()
  if (!response.ok) throw new Error(result.error?.message ?? "Request failed")
  return result as T
}
export async function passkeyLogin(stageToken: string, signal?: AbortSignal) {
  const { options, challengeId } = await securityRequest<{ options: PublicKeyCredentialRequestOptionsJSON; challengeId: string }>("passkey/options", { stageToken }, signal)
  signal?.throwIfAborted()
  const cancel = () => WebAuthnAbortService.cancelCeremony()
  signal?.addEventListener("abort", cancel, { once: true })
  try {
    const response = await startAuthentication({ optionsJSON: options })
    signal?.throwIfAborted()
    await securityRequest("passkey/verify", { response, challengeId, stageToken }, signal)
  } finally {
    signal?.removeEventListener("abort", cancel)
  }
}
export async function registerPasskey(password: string, code: string, name: string) {
  const { options, challengeId } = await securityRequest<{ options: PublicKeyCredentialCreationOptionsJSON; challengeId: string }>("register/options", { password, code })
  const response = await startRegistration({ optionsJSON: options })
  await securityRequest("register/verify", { response, challengeId, name })
}
