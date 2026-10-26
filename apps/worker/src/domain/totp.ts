import { randomBytes, toBytes } from "./bytes.ts"
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
export function newTotpSecret(): string {
  let bits = 0, value = 0, result = ""
  for (const byte of randomBytes(20)) {
    value = (value << 8) | byte; bits += 8
    while (bits >= 5) { bits -= 5; result += alphabet[(value >>> bits) & 31] }
  }
  return result
}
export async function totp(secret: string, step: number): Promise<string> {
  let bits = 0, value = 0
  const bytes: number[] = []
  for (const char of secret) {
    const digit = alphabet.indexOf(char)
    if (digit < 0) throw new Error("Invalid TOTP secret")
    value = (value << 5) | digit; bits += 5
    if (bits >= 8) { bits -= 8; bytes.push((value >>> bits) & 255) }
  }
  const counter = new Uint8Array(8)
  new DataView(counter.buffer).setBigUint64(0, BigInt(step))
  const key = await crypto.subtle.importKey("raw", toBytes(new Uint8Array(bytes)), { name: "HMAC", hash: "SHA-1" }, false, ["sign"])
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter))
  const offset = mac[19] & 15
  const code = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff
  return String(code % 1000000).padStart(6, "0")
}
export async function matchTotp(secret: string, code: string, now = Date.now()): Promise<number | null> {
  if (!/^\d{6}$/.test(code)) return null
  const step = Math.floor(now / 30000)
  for (const candidate of [step, step - 1, step + 1]) {
    if (await totp(secret, candidate) === code) return candidate
  }
  return null
}
