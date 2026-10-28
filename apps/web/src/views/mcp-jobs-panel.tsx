import { useCallback,useEffect,useState } from 'react'
import { api,type McpJob } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { AlertDialog,AlertDialogAction,AlertDialogCancel,AlertDialogContent,AlertDialogDescription,AlertDialogFooter,AlertDialogHeader,AlertDialogTitle } from '@/components/ui/alert-dialog'
import { useTranslation } from 'react-i18next'
export function McpJobsPanel(){
 const {i18n}=useTranslation(),zh=i18n.language.startsWith('zh')
 const [jobs,setJobs]=useState<McpJob[]>([]),[error,setError]=useState(''),[busy,setBusy]=useState(false),[review,setReview]=useState<McpJob|null>(null)
 const load=useCallback(async()=>{try{setJobs((await api.mcpJobs()).jobs);setError('')}catch{setError(zh?'无法加载任务':'Could not load jobs')}},[zh])
 useEffect(()=>{void load();const timer=setInterval(()=>void load(),5000);return()=>clearInterval(timer)},[load])
 async function act(job:McpJob,action:'approve'|'reject'|'cancel'){
  setBusy(true)
  try{if(action==='cancel')await api.cancelMcpJob(job.id);else await api.reviewMcpJob(job.id,job.command_hash,action);setReview(null);await load()}
  catch{setError(zh?'操作失败：任务、权限或目标可能已变化，请刷新后重试':'Operation failed. Reload to check task, target and permissions.')}
  finally{setBusy(false)}
 }
 return <div className="flex flex-col gap-3">
  <h3 className="text-[15px] font-semibold">{zh?'MCP 命令任务':'MCP command jobs'}</h3>
  <p className="text-sm text-muted-foreground">{zh?'机器只能提交任务；批准后须由机器启动一次。批准绑定下方主机、账号、完整命令和限制，5 分钟内有效。命令以专用账号执行，可能修改该账号可访问的数据。':'Machines submit proposals; a human approves and the machine starts once. Approval binds the exact host, account, command and limits for 5 minutes. Commands can modify data accessible to the dedicated account.'}</p>
  <Button variant="outline" onClick={()=>void load()}>{zh?'刷新任务':'Refresh jobs'}</Button>
  {error&&<p role="alert" className="text-sm text-danger">{error}</p>}
  {!jobs.length&&<p className="text-sm text-muted-foreground">{zh?'暂无任务':'No jobs'}</p>}
  {jobs.map(job=><section key={job.id} className="min-w-0 space-y-2 rounded-lg border border-border p-3">
   <p className="break-all text-sm font-medium">{job.agent_id} · {job.status}</p>
   <p className="break-all text-xs text-muted-foreground">{job.target.username}@{job.target.host}:{job.target.port} · {job.timeout_seconds}s · {job.max_output_bytes} bytes</p>
   <p className="break-all text-xs text-muted-foreground">{job.target.fingerprint}</p>
   <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-2 text-xs">{job.command??(zh?'命令已按保留策略清理':'Command cleared by retention policy')}</pre>
   <p className="break-all text-xs text-muted-foreground">{job.id}</p>
   {job.status==='pending'&&<div className="flex gap-2"><Button disabled={busy} onClick={()=>setReview(job)}>{zh?'审核并批准':'Review and approve'}</Button><Button variant="outline" disabled={busy} onClick={()=>void act(job,'reject')}>{zh?'拒绝':'Reject'}</Button></div>}
   {['pending','approved','queued','running'].includes(job.status)&&<Button variant="outline" disabled={busy||!!job.cancel_requested} onClick={()=>void act(job,'cancel')}>{job.cancel_requested?(zh?'取消中':'Cancelling'):zh?'取消任务':'Cancel job'}</Button>}
   {job.result&&<><p className="text-xs">{zh?'退出码':'Exit code'}: {job.result.exitCode??'—'} · {job.outcome}{job.result.remoteStopConfirmed?' · stop confirmed':''}</p><pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-2 text-xs">{job.result.stdout}</pre></>}
  </section>)}
  <AlertDialog open={!!review} onOpenChange={open=>!open&&!busy&&setReview(null)}><AlertDialogContent><AlertDialogHeader>
   <AlertDialogTitle>{zh?'批准这条命令？':'Approve this exact command?'}</AlertDialogTitle>
   <AlertDialogDescription>{review?.target.username}@{review?.target.host}:{review?.target.port} · {review?.timeout_seconds}s · {review?.max_output_bytes} bytes</AlertDialogDescription>
   <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-3 text-sm">{review?.command}</pre>
  </AlertDialogHeader><AlertDialogFooter><AlertDialogCancel disabled={busy}>{zh?'返回':'Back'}</AlertDialogCancel><AlertDialogAction disabled={busy} onClick={event=>{event.preventDefault();if(review)void act(review,'approve')}}>{zh?'批准一次':'Approve once'}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
 </div>
}
