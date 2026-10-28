import { cancelJob,getJob,jobView,reviewJob,type JobEnv } from '../domain/mcp-jobs.ts'
export async function handleJobAdmin(request:Request,env:JobEnv,path:string):Promise<Response>{
 const headers={'Cache-Control':'no-store'}
 const match=/^\/api\/mcp\/jobs(?:\/([a-f0-9-]{36})(?:\/(review|cancel))?)?$/.exec(path)
 if(!match)return Response.json({error:'NOT_FOUND'},{status:404,headers})
 try{
  const [,id,action]=match
  if(request.method==='GET' && !action){
   if(id){const job=await getJob(env.DB,id);if(!job)throw new Error('JOB_NOT_FOUND');return Response.json({job:await jobView(env,job)},{headers})}
   const rows=await env.DB.prepare('SELECT * FROM mcp_jobs ORDER BY created_at DESC LIMIT 50').all<import('../domain/mcp-jobs.ts').Job>()
   return Response.json({jobs:await Promise.all(rows.results.map(j=>jobView(env,j)))},{headers})
  }
  if(request.method!=='POST' || !id)return new Response(null,{status:405,headers})
  if(action==='review'){
   const raw=await request.text();if(raw.length>1024)throw new Error('INVALID_ARGUMENTS')
   const input=JSON.parse(raw);await reviewJob(env,id,input)
  }else if(action==='cancel'){
   const job=await getJob(env.DB,id);if(!job)throw new Error('JOB_NOT_FOUND');await cancelJob(env,job)
  }else return new Response(null,{status:405,headers})
  return Response.json({ok:true},{headers})
 }catch(e){const reason=e instanceof Error && ['JOB_NOT_FOUND','INVALID_ARGUMENTS','APPROVAL_INVALID','APPROVAL_EXPIRED','TARGET_CHANGED','ACCESS_DENIED','EXEC_PROFILE_REQUIRED'].includes(e.message)?e.message:'JOB_OPERATION_FAILED';return Response.json({error:reason},{status:409,headers})}
}
