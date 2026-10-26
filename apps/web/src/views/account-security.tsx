import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { registerPasskey, securityRequest, type SecurityStatus } from "@/lib/account-security"

export function AccountSecurity() {
  const { i18n } = useTranslation(), zh = i18n.language.startsWith("zh")
  const text = (cn: string, en: string) => zh ? cn : en
  const [status, setStatus] = useState<SecurityStatus | null>(null)
  const [password, setPassword] = useState(""), [code, setCode] = useState(""), [name, setName] = useState("")
  const [busy, setBusy] = useState(false)
  const passwordInput = useRef<HTMLInputElement>(null)
  const [proofError, setProofError] = useState<string | null>(null)
  const [loadError, setLoadError] = useState(false)
  function requireProof(): boolean {
    if (!password) {
      setProofError(text("请先输入当前密码，再执行此操作。", "Enter your current password to continue."))
      passwordInput.current?.focus()
      return false
    }
    if (status?.totpEnabled && !code) {
      setProofError(text("请同时输入动态码或恢复码。", "Also enter an authenticator or recovery code."))
      return false
    }
    setProofError(null)
    return true
  }
  const [setup, setSetup] = useState<{ secret: string; uri: string; challengeId: string } | null>(null)
  const [codes, setCodes] = useState<string[]>([])
  const refresh = async () => { setStatus(await securityRequest<SecurityStatus>("status")); setLoadError(false) }
  useEffect(() => { void refresh().catch(() => setLoadError(true)) }, [])
  async function run(action: () => Promise<void>, needsProof = true) {
    if (needsProof && !requireProof()) return
    setBusy(true)
    try { await action(); setCode(""); await refresh() }
    catch (error) { toast.error(error instanceof Error ? error.message : text("操作失败", "Request failed")) }
    finally { setBusy(false) }
  }
  const proof = { password, code }
  return <section className="mt-5 flex flex-col gap-3 border-t pt-4">
    <h3 className="text-[15px] font-semibold">{text("通行密钥与两步验证", "Passkeys and two-step verification")}</h3>
    <p className="text-xs text-muted-foreground">{text("密码验证后优先使用通行密钥；验证器动态码可作为备用方式。更改安全设置后，其他会话将退出。", "After password verification, passkeys are preferred with authenticator codes as fallback. Security changes sign out other sessions.")}</p>
    <label className="text-sm">{text("当前密码（管理安全设置时验证）", "Current password to manage security")}
      <Input ref={passwordInput} type="password" autoComplete="current-password" value={password} onChange={e => { setPassword(e.target.value); setProofError(null) }} aria-invalid={!!proofError} />
    </label>
    <p className="text-xs text-muted-foreground">{text("添加或移除验证方式前需验证当前密码。", "Your current password is required before adding or removing verification methods.")}</p>
    {proofError && <p className="text-xs text-danger" role="alert">{proofError}</p>}
    {!status && !loadError && <p className="text-xs text-muted-foreground" role="status">{text("正在加载安全设置…", "Loading security settings…")}</p>}
    {loadError && <div role="alert" className="text-sm">
      <p>{text("安全设置加载失败，请重试。", "Could not load security settings. Please retry.")}</p>
      <Button variant="outline" disabled={busy} onClick={() => void run(refresh, false)}>{text("重新加载", "Reload")}</Button>
    </div>}
    {status?.totpEnabled && <label className="text-sm">{text("动态码或一次性恢复码", "Authenticator or recovery code")}
      <Input autoComplete="one-time-code" value={code} onChange={e => setCode(e.target.value)} />
    </label>}
    <label className="text-sm">{text("通行密钥名称", "Passkey name")}<Input value={name} maxLength={64} onChange={e => setName(e.target.value)} /></label>
    <Button variant="outline" disabled={busy || !status} onClick={() => void run(async () => {
      await registerPasskey(password, code, name); setPassword(""); toast.success(text("通行密钥已添加", "Passkey added"))
    })}>{text("添加通行密钥 / 安全密钥", "Add passkey / security key")}</Button>
    {status?.passkeys.map(key => <div key={key.id} className="flex items-center justify-between gap-2 text-sm">
      <span className="truncate">{key.name}</span><Button size="sm" variant="outline" disabled={busy} onClick={() => void run(async () => { await securityRequest("passkey/delete", { ...proof, id: key.id }); setPassword("") })}>{text("移除", "Remove")}</Button>
    </div>)}
    {status && <p className="text-sm">{text("两步验证：", "Two-step verification: ")}{status.totpEnabled ? text("已启用", "Enabled") : text("未启用", "Disabled")}{status.totpEnabled && ` · ${text("剩余恢复码", "Recovery codes remaining")}: ${status.recoveryCodesRemaining}`}</p>}
    {status?.totpEnabled ? <Button variant="outline" disabled={busy || !status} onClick={() => void run(async () => { await securityRequest("totp/disable", proof); setCodes([]); setPassword("") })}>{text("关闭两步验证", "Disable two-step verification")}</Button> :
      <Button variant="outline" disabled={busy || !status} onClick={() => void run(async () => { setSetup(await securityRequest("totp/setup", proof)); setCodes([]) })}>{text("设置验证器", "Set up authenticator")}</Button>}
    {setup && <div className="flex flex-col gap-3 rounded border p-3">
      <p className="text-xs">{text("在验证器应用中手动添加账户，输入下方密钥（基于时间，6位，30秒）。随后输入动态码完成启用。", "Add an account manually in your authenticator with this key (time-based, 6 digits, 30 seconds), then enter its code.")}</p>
      <code className="break-all select-all text-sm">{setup.secret}</code>
      <a className="text-sm underline" href={setup.uri}>{text("在本机验证器中打开", "Open in authenticator")}</a>
      <label className="text-sm">{text("验证器动态码", "Authenticator code")}<Input autoComplete="one-time-code" inputMode="numeric" value={code} onChange={e => setCode(e.target.value)} /></label>
      <Button disabled={busy || !/^\d{6}$/.test(code)} onClick={() => void run(async () => {
        const result = await securityRequest<{ recoveryCodes: string[] }>("totp/enable", { challengeId: setup.challengeId, code }); setCodes(result.recoveryCodes); setSetup(null); setPassword("")
      }, false)}>{text("验证并启用", "Verify and enable")}</Button>
      <Button variant="outline" disabled={busy} onClick={() => { setSetup(null); setCode("") }}>{text("取消", "Cancel")}</Button>
    </div>}
    {codes.length > 0 && <div role="status" className="rounded border p-3 text-sm">
      <p>{text("请立即将恢复码保存在安全位置。仅显示一次，每个仅能使用一次。", "Save these recovery codes securely now. Shown once; each can be used once.")}</p>
      <pre className="my-3 select-all">{codes.join("\n")}</pre>
      <Button variant="outline" onClick={() => setCodes([])}>{text("已保存，隐藏恢复码", "Saved, hide codes")}</Button>
    </div>}
  </section>
}
