// Downloads are streamed into SHA-256; executable bytes are never saved or run.
import {createHash} from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
const urls={usermode:'https://files.matcha.pink/normal/usermode.exe',kernel:'https://files.matcha.pink/normal/kernel.exe',map:'https://files.matcha.pink/normal/map.exe'};
async function request(url,method='GET') {
  const r=await fetch(url,{method,redirect:'manual',cache:'no-store',signal:AbortSignal.timeout(180000)});
  if(!r.ok)throw Error('download server returned '+r.status);
  return r;
}
const headers=r=>({size:Number(r.headers.get('content-length')),etag:r.headers.get('etag'),modified:r.headers.get('last-modified')});
const same=(a,b)=>a.size===b.size&&a.etag===b.etag&&a.modified===b.modified;
const files={};
for(const [name,url]of Object.entries(urls)) {
  console.log('checking '+name+' download…');
  const before=headers(await request(url,'HEAD')),response=await request(url),during=headers(response);
  if(!Number.isSafeInteger(before.size)||before.size<1024||before.size>128*1024*1024||!before.etag||!before.modified||!same(before,during))throw Error('unstable download metadata');
  const hash=createHash('sha256');let size=0,magic=[];
  for await(const chunk of response.body) {
    if(magic.length<2)magic.push(...chunk.slice(0,2-magic.length));
    size+=chunk.length;if(size>128*1024*1024)throw Error('download too large');hash.update(chunk);
  }
  if(size!==before.size||magic[0]!==77||magic[1]!==90)throw Error('incomplete or unexpected executable');
  if(!same(before,headers(await request(url,'HEAD'))))throw Error('download changed while hashing');
  files[name]={url,sha256:hash.digest('hex'),...before};console.log(name+' · '+size+' bytes · sha256 checked');
}
// Recheck the whole set, so a release changing mid-run never becomes an authoritative manifest.
for(const[name,url]of Object.entries(urls))if(!same(files[name],headers(await request(url,'HEAD'))))throw Error('release changed; retry');
const manifest={schema:1,checkedAt:new Date().toISOString(),files};
const out=path.resolve(process.argv[2]??new URL('release.json',import.meta.url).pathname.replace(/^\/([A-Za-z]:)/,'$1'));
await fs.mkdir(path.dirname(out),{recursive:true});const temp=out+'.pending';
await fs.writeFile(temp,JSON.stringify(manifest,null,2)+'\n');await fs.rename(temp,out);
console.log('saved verified release manifest: '+out);
if(process.argv.includes('--publish')) {
  const key=process.env.FIXER_RELEASE_UPDATE_KEY;
  if(!/^[a-f0-9]{64}$/.test(key??''))throw Error('release updater credential is not configured');
  const result=await fetch('https://adorablewhale.world/api/internal/fixer/release',{method:'POST',redirect:'manual',
    headers:{'content-type':'application/json',authorization:'Bearer '+key},body:JSON.stringify(manifest),signal:AbortSignal.timeout(30000)});
  if(result.status!==200)throw Error('release publication failed with status '+result.status);
  console.log('published verified reference');
}
