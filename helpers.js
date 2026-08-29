import { parse } from 'csv-parse/sync';
import { driveApi } from './google.js';

export function cleanHeader(s){
  return String(s ?? '').replace(/^\uFEFF/,'').trim();
}
export function num(v){
  if(v===null || v===undefined || v==='') return 0;
  const n=Number(String(v).replace(/,/g,'').trim());
  return Number.isFinite(n)?n:0;
}
export function dateOnly(v){
  const s=String(v??'').trim();
  const m=s.match(/^(\d{4})-(\d{2})-(\d{2})/);
  return m?`${m[1]}-${m[2]}-${m[3]}`:'';
}
export function normalizeSub(v){
  return String(v??'').trim().replace(/-+$/,'') || '(No SubID)';
}
export function dayDiff(a,b){
  return Math.round((new Date(b+'T00:00:00')-new Date(a+'T00:00:00'))/86400000);
}
export function round2(n){ return Math.round((Number(n)||0)*100)/100; }

export async function downloadText(fileId){
  const drive=driveApi();
  const r=await drive.files.get({fileId,alt:'media'},{responseType:'stream'});
  return await new Promise((resolve,reject)=>{
    const chunks=[];
    r.data.on('data',c=>chunks.push(Buffer.isBuffer(c)?c:Buffer.from(c)));
    r.data.on('end',()=>resolve(Buffer.concat(chunks).toString('utf8').replace(/^\uFEFF/,'')));
    r.data.on('error',reject);
  });
}

export async function parseCsvDrive(fileId){
  const text=await downloadText(fileId);
  const rows=parse(text,{
    bom:true,
    relax_column_count:true,
    relax_quotes:true,
    skip_empty_lines:true
  });
  if(!rows.length) return {headers:[],rows:[]};
  return {headers:rows[0].map(cleanHeader),rows:rows.slice(1)};
}

export function findIndex(headers,candidates,required=true){
  for(const c of candidates){
    const i=headers.indexOf(c);
    if(i>=0) return i;
  }
  if(required) throw new Error('Missing column: '+candidates.join(' / '));
  return -1;
}

export async function findLatestInFolder(folderId,prefix){
  const drive=driveApi();
  const q=[`'${folderId}' in parents`,`trashed=false`,`name contains '${prefix.replace(/'/g,"\\'")}'`].join(' and ');
  const r=await drive.files.list({
    q,
    orderBy:'modifiedTime desc',
    pageSize:100,
    fields:'files(id,name,mimeType,modifiedTime,size,webViewLink)'
  });
  const matches=(r.data.files||[]).filter(f=>String(f.name||'').startsWith(prefix));
  return matches[0]||null;
}

export function uniqueCount(rows,idx){
  return new Set(rows.map(r=>String(r[idx]??'').trim()).filter(Boolean)).size;
}
export function sumRows(rows,idx){
  return rows.reduce((s,r)=>s+num(r[idx]),0);
}
