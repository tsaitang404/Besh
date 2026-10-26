import { startAuthentication, startRegistration } from "@simplewebauthn/browser"
import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser"
export type SecurityStatus = { totpEnabled: boolean; passkeys: { id: string; name: string; created_at: number }[]; recoveryCodesRemaining: number }
export async function securityRequest<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(`/api/auth/security/${path}`, {
    method: body === undefined ? "GET" : "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
  const result = await response.json()
  if (!response.ok) throw new Error(result.error?.message ?? "Request failed")
  return result as T
}
export async function passkeyLogin() {
  const { options, challengeId } = await securityRequest<{ options: PublicKeyCredentialRequestOptionsJSON; challengeId: string }>("passkey/options", {})
  const response = await startAuthentication({ optionsJSON: options })
  await securityRequest("passkey/verify", { response, challengeId })
}
export async function registerPasskey(password: string, code: string, name: string) {
  const { options, challengeId } = await securityRequest<{ options: PublicKeyCredentialCreationOptionsJSON; challengeId: string }>("register/options", { password, code })
  const response = await startRegistration({ optionsJSON: options })
  await securityRequest("register/verify", { response, challengeId, name })
}
