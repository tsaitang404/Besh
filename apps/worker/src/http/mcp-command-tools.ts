import { submitJob,ownedJob,jobView,cancelJob,type JobEnv } from '../domain/mcp-jobs.ts'
import type { MachineAgent } from '../domain/mcp-store.ts'
export async function commandTool(env:JobEnv,agent:MachineAgent,name:string,args:Record<string,unknown>,origin:string):Promise<unknown>{
 if(name==='command_submit'){
  const job=await submitJob(env,agent,args)
  return {...await jobView(env,job),approvalUrl:origin+'/#mcp-jobs',message:'Requires human approval in Besh. This MCP has no approval tool.'}
 }
 const job=await ownedJob(env,agent,String(args.jobId),name)
 if(name==='command_status')return jobView(env,job)
 if(name==='command_cancel'){await cancelJob(env,job);return {jobId:job.id,cancelRequested:true}}
 if(name==='command_start'){
  const r=await env.COMMAND_JOBS.get(env.COMMAND_JOBS.idFromName(job.id)).fetch(new Request('https://job/start',{method:'POST',body:JSON.stringify({jobId:job.id,agentId:agent.id})}))
  if(!r.ok)throw new Error('APPROVAL_OR_ACCESS_INVALID')
  return {jobId:job.id,status:'queued',message:'Poll command_status for the terminal result. Never resubmit to retry an ambiguous execution.'}
 }
 throw new Error('INVALID_ARGUMENTS')
}
