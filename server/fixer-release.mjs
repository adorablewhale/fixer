import {timingSafeEqual} from 'node:crypto';
export const MATCHA_DOWNLOADS={usermode:'https://files.matcha.pink/normal/usermode.exe',kernel:'https://files.matcha.pink/normal/kernel.exe',map:'https://files.matcha.pink/normal/map.exe'};
const cache=new WeakMap();
const json=(b,status=200)=>new Response(JSON.stringify(b),{status,headers:{'content-type':'application/json','cache-control':'no-store'}});
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&Object.keys(v).every(k=>keys.includes(k));
export function validRelease(v) {
  return exact(v,['schema','checkedAt','files'])&&v.schema===1&&typeof v.checkedAt==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v.checkedAt)&&Number.isFinite(Date.parse(v.checkedAt))&&
    exact(v.files,Object.keys(MATCHA_DOWNLOADS))&&Object.entries(MATCHA_DOWNLOADS).every(([n,url])=>{
      const f=v.files[n];return exact(f,['url','sha256','size','etag','modified'])&&f.url===url&&typeof f.sha256==='string'&&/^[a-f0-9]{64}$/.test(f.sha256)&&
        Number.isSafeInteger(f.size)&&f.size>=1024&&f.size<=128*1024*1024&&typeof f.etag==='string'&&/^[\x20-\x7e]{1,160}$/.test(f.etag)&&
        typeof f.modified==='string'&&f.modified.length<80&&Number.isFinite(Date.parse(f.modified));
    });
}
async function current(env,manifest) {
  const fetcher=env.FIXER_RELEASE_FETCH??fetch;
  const responses=await Promise.all(Object.values(manifest.files).map(f=>fetcher(f.url,{method:'HEAD',redirect:'manual',cache:'no-store',signal:AbortSignal.timeout(8000)})));
  return responses.every((r,i)=>{
    const f=Object.values(manifest.files)[i];return r.status===200&&Number(r.headers.get('content-length'))===f.size&&r.headers.get('etag')===f.etag&&r.headers.get('last-modified')===f.modified;
  });
}
export function createFixerRelease(env) {
  async function readManifest() {
    const row=await env.DB.prepare('SELECT manifest FROM fixer_releases WHERE id=1').bind().first();
    if(row)return JSON.parse(row.manifest);
    const asset=await env.ASSETS.fetch(new Request((env.ORIGIN??'https://adorablewhale.world')+'/fixer-release.json'));
    if(!asset.ok)throw Error('reference unavailable');return asset.json();
  }
  async function read(req) {
    if(req.method!=='GET'||new URL(req.url).search)return json({ok:false,error:'invalid request'},400);
    const peer=req.headers.get('cf-connecting-ip')??'local';
    if(!(await env.API_LIMIT.limit({key:'fixer-reference:'+peer})).success)return json({ok:false,error:'please slow down'},429);
    let state=cache.get(env);
    if(state&&Date.now()-state.at<60000)return json(state.value,state.status);
    if(state?.pending){await state.pending;return json(state.value,state.status);}
    state={at:0};cache.set(env,state);
    state.pending=(async()=>{
      try {
        const manifest=await readManifest();
        if(!validRelease(manifest)||Date.now()-Date.parse(manifest.checkedAt)>24*3600*1000||Date.parse(manifest.checkedAt)>Date.now()+300000||!await current(env,manifest))throw Error('reference needs refresh');
        state.value={ok:true,checkedAt:manifest.checkedAt,upstreamCheckedAt:new Date().toISOString(),files:manifest.files};state.status=200;
      }catch{state.value={ok:false,error:'current release reference unavailable; use the loader to check for updates'};state.status=503;}
      state.at=Date.now();state.pending=null;
    })();
    await state.pending;return json(state.value,state.status);
  }
  async function publish(req) {
    const url=new URL(req.url);
    if(req.method!=='POST'||url.protocol!=='https:'||url.origin!==env.ORIGIN||url.search)return json({ok:false},403);
    const provided=(req.headers.get('authorization')??'').replace(/^Bearer /,''),expected=env.FIXER_RELEASE_UPDATE_KEY;
    if(!(await env.AUTH_LIMIT.limit({key:'fixer-release-write:'+(req.headers.get('cf-connecting-ip')??'local')})).success)return json({ok:false},429);
    if(!/^[a-f0-9]{64}$/.test(expected??'')||!/^[a-f0-9]{64}$/.test(provided)||!timingSafeEqual(Buffer.from(expected),Buffer.from(provided)))return json({ok:false},401);
    try {
      if(!req.headers.get('content-type')?.startsWith('application/json'))throw Error('json required');
      const reader=req.body?.getReader();if(!reader)throw Error('body required');let bytes=0,raw='';const decoder=new TextDecoder('utf-8',{fatal:true});
      for(;;){const{value,done}=await reader.read();if(done)break;bytes+=value.length;if(bytes>4096){await reader.cancel();throw Error('too large');}raw+=decoder.decode(value,{stream:true});}raw+=decoder.decode();
      const manifest=JSON.parse(raw);
      if(!validRelease(manifest)||Math.abs(Date.now()-Date.parse(manifest.checkedAt))>1800000||!await current(env,manifest))throw Error('invalid reference');
      await env.DB.prepare('INSERT INTO fixer_releases(id,manifest) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET manifest=excluded.manifest').bind(JSON.stringify(manifest)).run();
      cache.delete(env);return json({ok:true});
    }catch{return json({ok:false,error:'invalid reference'},400);}
  }
  return{read,publish};
}
