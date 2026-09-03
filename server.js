import 'dotenv/config';
import express from 'express';
import crypto, { randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { oauthClient,scriptApi,sheetsApi,driveApi,assertAllowedScript,assertAllowedSheet,scriptAccessMode } from './google.js';
import {
  parseCsvDrive,findIndex,findLatestInFolder,dateOnly,num,normalizeSub,dayDiff,
  round2,uniqueCount,sumRows
} from './helpers.js';

const app=express();
app.use(express.json({limit:'16mb'}));
app.use('/assets',express.static('public'));
app.use(express.urlencoded({extended:false}));

// Safe request logger: never prints Authorization headers, tokens, secrets, codes, or query values.
app.use((req,res,next)=>{
  const started=Date.now();
  const queryKeys=Object.keys(req.query||{});
  const bodyKeys=(req.body && typeof req.body==='object')?Object.keys(req.body):[];
  res.on('finish',()=>{
    const extra=[];
    if(queryKeys.length) extra.push(`queryKeys=${queryKeys.join(',')}`);
    if(bodyKeys.length) extra.push(`bodyKeys=${bodyKeys.join(',')}`);
    if(req.get('mcp-session-id')) extra.push('mcpSession=present');
    console.log(`[HTTP] ${req.method} ${req.path} -> ${res.statusCode} (${Date.now()-started}ms)${extra.length?' | '+extra.join(' | '):''}`);
  });
  next();
});

const sessions=new Map();
const authCodes=new Map();
const BASE=(process.env.PUBLIC_BASE_URL||'').replace(/\/$/,'');

const OAUTH_SCOPES=[
  'https://www.googleapis.com/auth/script.projects',
  'https://www.googleapis.com/auth/script.deployments',
  'https://www.googleapis.com/auth/script.processes',
  'https://www.googleapis.com/auth/spreadsheets',
  'https://www.googleapis.com/auth/drive.readonly'
];

function signingKey(){
  const s=(process.env.SPARK_TOKEN_SIGNING_SECRET||'');
  if(s.length<32) throw new Error('SPARK_TOKEN_SIGNING_SECRET must be at least 32 characters');
  return new TextEncoder().encode(s);
}
async function mintAccessToken(clientId){
  return await new SignJWT({scope:'mcp'})
    .setProtectedHeader({alg:'HS256'})
    .setIssuer(BASE).setAudience(`${BASE}/mcp`).setSubject(clientId)
    .setIssuedAt().setExpirationTime('1h').sign(signingKey());
}
async function mintRefreshToken(clientId){
  return await new SignJWT({typ:'refresh_token',scope:'mcp'})
    .setProtectedHeader({alg:'HS256'})
    .setIssuer(BASE).setAudience(`${BASE}/oauth/token`).setSubject(clientId)
    .setIssuedAt().setExpirationTime('30d').sign(signingKey());
}
async function validMcpBearer(req){
  const h=req.get('authorization')||'';
  if(!h.startsWith('Bearer ')) return false;
  const token=h.slice(7);
  const legacy=(process.env.MCP_BEARER_TOKEN||'').trim();
  if(legacy && token===legacy) return true;
  try{ await jwtVerify(token,signingKey(),{issuer:BASE,audience:`${BASE}/mcp`}); return true; }
  catch{return false;}
}
async function requireMcpAuth(req,res,next){
  const ok=await validMcpBearer(req);
  console.log(`[MCP AUTH] authorized=${ok} method=${req.method} session=${req.get('mcp-session-id')?'present':'none'}`);
  if(ok) return next();
  const meta=`${BASE}/.well-known/oauth-protected-resource`;
  res.set('WWW-Authenticate',`Bearer resource_metadata="${meta}"`);
  return res.status(401).json({error:'unauthorized'});
}
function pkceS256(v){ return crypto.createHash('sha256').update(v).digest('base64url'); }
function esc(v){ return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

// OAuth metadata for Spark / MCP clients
app.get('/.well-known/oauth-protected-resource',(_req,res)=>res.json({
  resource:`${BASE}/mcp`, authorization_servers:[BASE], bearer_methods_supported:['header'], scopes_supported:['mcp']
}));
app.get('/.well-known/oauth-authorization-server',(_req,res)=>res.json({
  issuer:BASE,
  authorization_endpoint:`${BASE}/oauth/authorize`,
  token_endpoint:`${BASE}/oauth/token`,
  response_types_supported:['code'], grant_types_supported:['authorization_code','refresh_token'],
  token_endpoint_auth_methods_supported:['client_secret_post','client_secret_basic'],
  code_challenge_methods_supported:['S256','plain'], scopes_supported:['mcp']
}));

app.get('/oauth/authorize',(req,res)=>{
  const {response_type,client_id,redirect_uri,state,code_challenge,code_challenge_method,scope}=req.query;
  console.log(`[OAUTH authorize] response_type=${response_type||'none'} clientMatch=${client_id===process.env.SPARK_OAUTH_CLIENT_ID} redirectMatch=${redirect_uri===process.env.SPARK_REDIRECT_URI} pkce=${code_challenge?'yes':'no'} method=${code_challenge_method||'none'} state=${state?'yes':'no'}`);
  if(response_type!=='code') return res.status(400).send('Unsupported response_type');
  if(client_id!==process.env.SPARK_OAUTH_CLIENT_ID) return res.status(400).send('Unknown client_id');
  if(redirect_uri!==process.env.SPARK_REDIRECT_URI) return res.status(400).send('redirect_uri mismatch');
  const qs=new URLSearchParams({client_id:String(client_id),redirect_uri:String(redirect_uri),state:String(state||''),code_challenge:String(code_challenge||''),code_challenge_method:String(code_challenge_method||''),scope:String(scope||'mcp')}).toString();
  res.send(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font-family:Arial;background:#f6f7f9}.card{max-width:560px;margin:70px auto;background:#fff;border:1px solid #ddd;border-radius:16px;padding:28px}.btn{padding:12px 18px;border:0;border-radius:10px;background:#111;color:#fff;font-weight:700;cursor:pointer}</style></head><body><div class="card"><h2>อนุญาต Spark เชื่อมต่อ MCP</h2><p>อนุญาตให้ Spark เรียกเครื่องมือ Apps Script, Google Sheets และ Shopee CSV ผ่าน MCP นี้</p><p>Client: ${esc(client_id)}</p><form method="post" action="/oauth/approve?${qs}"><button class="btn">อนุญาต</button></form></div></body></html>`);
});
app.post('/oauth/approve',(req,res)=>{
  const {client_id,redirect_uri,state,code_challenge,code_challenge_method,scope}=req.query;
  console.log(`[OAUTH approve] clientMatch=${client_id===process.env.SPARK_OAUTH_CLIENT_ID} redirectMatch=${redirect_uri===process.env.SPARK_REDIRECT_URI} pkce=${code_challenge?'yes':'no'} method=${code_challenge_method||'none'} state=${state?'yes':'no'}`);
  if(client_id!==process.env.SPARK_OAUTH_CLIENT_ID) return res.status(400).send('Unknown client_id');
  if(redirect_uri!==process.env.SPARK_REDIRECT_URI) return res.status(400).send('redirect_uri mismatch');
  const code=crypto.randomBytes(32).toString('base64url');
  authCodes.set(code,{client_id,redirect_uri,code_challenge,code_challenge_method,scope:scope||'mcp',expires:Date.now()+300000});
  const u=new URL(String(redirect_uri)); u.searchParams.set('code',code); if(state)u.searchParams.set('state',String(state)); res.redirect(u.toString());
});
app.post('/oauth/token',async(req,res)=>{
  try{
    let clientId=req.body.client_id||'', clientSecret=req.body.client_secret||'';
    const basic=req.get('authorization')||'';
    if(basic.startsWith('Basic ')){ const [u,p]=Buffer.from(basic.slice(6),'base64').toString('utf8').split(':'); clientId=u||clientId; clientSecret=p||clientSecret; }
    const clientMatch=clientId===process.env.SPARK_OAUTH_CLIENT_ID;
    const secretMatch=clientSecret===process.env.SPARK_OAUTH_CLIENT_SECRET;
    console.log(`[OAUTH token] grant_type=${req.body.grant_type||'none'} auth=${basic.startsWith('Basic ')?'basic':'post-or-none'} clientMatch=${clientMatch} secretMatch=${secretMatch} redirectProvided=${req.body.redirect_uri?'yes':'no'} verifier=${req.body.code_verifier?'yes':'no'}`);
    if(!clientMatch || !secretMatch) return res.status(401).json({error:'invalid_client'});

    if(req.body.grant_type==='refresh_token'){
      try{
        const {payload}=await jwtVerify(req.body.refresh_token||'',signingKey(),{issuer:BASE,audience:`${BASE}/oauth/token`});
        if(payload.typ!=='refresh_token' || payload.sub!==clientId) throw new Error('invalid refresh token');
        return res.json({access_token:await mintAccessToken(clientId),token_type:'Bearer',expires_in:3600,scope:'mcp'});
      }catch{return res.status(400).json({error:'invalid_grant'});}
    }

    if(req.body.grant_type!=='authorization_code') return res.status(400).json({error:'unsupported_grant_type'});
    const rec=authCodes.get(req.body.code);
    if(!rec || rec.expires<Date.now() || rec.client_id!==clientId) return res.status(400).json({error:'invalid_grant'});
    if(req.body.redirect_uri && rec.redirect_uri!==req.body.redirect_uri) return res.status(400).json({error:'invalid_grant'});
    if(rec.code_challenge){ const verifier=req.body.code_verifier||''; const actual=rec.code_challenge_method==='S256'?pkceS256(verifier):verifier; if(actual!==rec.code_challenge)return res.status(400).json({error:'invalid_grant',error_description:'PKCE verification failed'}); }
    authCodes.delete(req.body.code);
    res.json({access_token:await mintAccessToken(clientId),refresh_token:await mintRefreshToken(clientId),token_type:'Bearer',expires_in:3600,scope:'mcp'});
  }catch(e){res.status(500).json({error:'server_error',error_description:String(e.message||e)});}
});

app.get('/auth/start',(_req,res)=>{
  const url=oauthClient().generateAuthUrl({access_type:'offline',prompt:'consent',scope:OAUTH_SCOPES});
  res.redirect(url);
});

app.get('/oauth2callback',async(req,res)=>{
  try{
    const code=req.query.code;
    if(!code) return res.status(400).send('Missing OAuth code');
    const {tokens}=await oauthClient().getToken(code);
    const rt=tokens.refresh_token||'';
    if(!rt) return res.send('<h2>OAuth สำเร็จแต่ไม่มี refresh token</h2><p>Revoke app access แล้วเปิด /auth/start ใหม่</p>');
    const safe=rt.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    res.send(`<h2>OAuth สำเร็จ</h2><p>ใส่ค่านี้ใน Render Environment: GOOGLE_REFRESH_TOKEN</p><pre style="white-space:pre-wrap;word-break:break-all">${safe}</pre><p><b>ห้ามแชร์ token</b></p>`);
  }catch(e){res.status(500).send('OAuth failed: '+String(e.message||e));}
});



// ===== v4.5 Web Tool / Chat Console =====
function requireWebAdmin(req,res,next){
  const expected=(process.env.WEB_ADMIN_TOKEN||'').trim();
  if(!expected) return res.status(503).json({ok:false,error:'WEB_ADMIN_TOKEN is not configured'});
  const h=req.get('authorization')||'';
  const token=h.startsWith('Bearer ')?h.slice(7):'';
  if(token!==expected) return res.status(401).json({ok:false,error:'Unauthorized'});
  next();
}
function webResolveScriptId(inputId){
  const configured=(process.env.ALLOWED_SCRIPT_ID||'').trim();
  const id=String(inputId||configured||'').trim();
  if(!id) throw new Error('No Apps Script project selected');
  assertAllowedScript(id);
  return id;
}
function webInferType(name,type){
  if(type) return type;
  const n=String(name||'').toLowerCase();
  if(n==='appsscript.json'||n.endsWith('.json')) return 'JSON';
  if(n.endsWith('.html')) return 'HTML';
  return 'SERVER_JS';
}
function webFileName(name){
  const n=String(name||'').trim();
  if(!n) throw new Error('File name is required');
  return n.replace(/\.(gs|html)$/i,'');
}
async function webGetProjectContent(scriptId){
  const id=webResolveScriptId(scriptId);
  const [meta,content]=await Promise.all([
    scriptApi().projects.get({scriptId:id}),
    scriptApi().projects.getContent({scriptId:id})
  ]);
  return {project:meta.data,files:content.data.files||[]};
}
async function webWriteFiles(scriptId,files,{backup=true}={}){
  const id=webResolveScriptId(scriptId), api=scriptApi();
  let backupVersion=null;
  if(backup){
    const v=await api.projects.versions.create({scriptId:id,requestBody:{description:'Web Tool backup before edit'}});
    backupVersion=v.data.versionNumber;
  }
  const current=(await api.projects.getContent({scriptId:id})).data.files||[];
  for(const f of files){
    const name=webFileName(f.name), type=webInferType(f.name,f.type), source=String(f.source??'');
    const i=current.findIndex(x=>x.name===name);
    const next={name,type,source};
    if(i>=0) current[i]=next; else current.push(next);
  }
  await api.projects.updateContent({scriptId:id,requestBody:{files:current}});
  return {ok:true,scriptId:id,backupVersion,filesWritten:files.map(f=>webFileName(f.name))};
}
async function webFindProjects(nameContains=''){
  const clauses=["mimeType='application/vnd.google-apps.script'","trashed=false"];
  if(nameContains){ const safe=String(nameContains).replace(/'/g,"\\'"); clauses.push(`name contains '${safe}'`); }
  const r=await driveApi().files.list({q:clauses.join(' and '),pageSize:100,orderBy:'modifiedTime desc',fields:'files(id,name,mimeType,modifiedTime,createdTime,webViewLink,parents)'});
  return r.data.files||[];
}

app.get('/tool',(_req,res)=>res.sendFile(process.cwd()+'/public/admin.html'));
app.get('/tool/',(_req,res)=>res.sendFile(process.cwd()+'/public/admin.html'));

app.get('/api/admin/status',requireWebAdmin,async(_req,res)=>{
  try{
    res.json({ok:true,version:'4.5.0',scriptAccessMode:scriptAccessMode(),geminiConfigured:!!process.env.GEMINI_API_KEY,defaultScriptId:(process.env.ALLOWED_SCRIPT_ID||'')?true:false});
  }catch(e){res.status(500).json({ok:false,error:String(e.message||e)});}
});
app.get('/api/admin/projects',requireWebAdmin,async(req,res)=>{
  try{res.json({ok:true,projects:await webFindProjects(req.query.q||'')});}
  catch(e){res.status(500).json({ok:false,error:String(e.message||e)});}
});
app.post('/api/admin/projects',requireWebAdmin,async(req,res)=>{
  try{
    const title=String(req.body.title||'').trim(); if(!title) return res.status(400).json({ok:false,error:'title required'});
    const requestBody={title}; if(req.body.parentId) requestBody.parentId=String(req.body.parentId);
    const r=await scriptApi().projects.create({requestBody});
    res.json({ok:true,project:r.data,note:scriptAccessMode()==='all'?'Ready to edit':'If access mode is locked, add the new scriptId to ALLOWED_SCRIPT_IDS.'});
  }catch(e){res.status(500).json({ok:false,error:String(e.message||e)});}
});
app.get('/api/admin/projects/:scriptId',requireWebAdmin,async(req,res)=>{
  try{res.json({ok:true,...await webGetProjectContent(req.params.scriptId)});}
  catch(e){res.status(500).json({ok:false,error:String(e.message||e)});}
});
app.put('/api/admin/projects/:scriptId/files',requireWebAdmin,async(req,res)=>{
  try{
    const files=Array.isArray(req.body.files)?req.body.files:[];
    if(!files.length) return res.status(400).json({ok:false,error:'files[] required'});
    res.json(await webWriteFiles(req.params.scriptId,files,{backup:req.body.backup!==false}));
  }catch(e){res.status(500).json({ok:false,error:String(e.message||e)});}
});
app.post('/api/admin/projects/:scriptId/version',requireWebAdmin,async(req,res)=>{
  try{
    const id=webResolveScriptId(req.params.scriptId);
    const r=await scriptApi().projects.versions.create({scriptId:id,requestBody:{description:String(req.body.description||'Created from Web Tool')}});
    res.json({ok:true,version:r.data});
  }catch(e){res.status(500).json({ok:false,error:String(e.message||e)});}
});
app.get('/api/admin/projects/:scriptId/deployments',requireWebAdmin,async(req,res)=>{
  try{
    const id=webResolveScriptId(req.params.scriptId);
    const r=await scriptApi().projects.deployments.list({scriptId:id,pageSize:100});
    res.json({ok:true,deployments:r.data.deployments||[]});
  }catch(e){res.status(500).json({ok:false,error:String(e.message||e)});}
});

function extractJsonObject(text){
  const clean=String(text||'').replace(/^```json\s*/i,'').replace(/```$/,'').trim();
  try{return JSON.parse(clean);}catch{}
  const a=clean.indexOf('{'), b=clean.lastIndexOf('}');
  if(a>=0&&b>a) return JSON.parse(clean.slice(a,b+1));
  throw new Error('AI returned invalid JSON');
}
async function callGeminiPlanner({message,scriptId,context}){
  const key=(process.env.GEMINI_API_KEY||'').trim();
  if(!key) throw new Error('GEMINI_API_KEY is not configured. Add it in Render Environment to use free-text AI chat.');
  const model=(process.env.GEMINI_MODEL||'gemini-2.5-flash').trim();
  const sys=`You are the controller for a private Google Apps Script web tool. Convert the Thai or English user request into ONE JSON object only. Never use markdown.\nAllowed actions:\n- {"action":"reply","reply":"..."}\n- {"action":"list_projects","query":""}\n- {"action":"read_project","scriptId":"optional"}\n- {"action":"create_project","title":"...","parentId":"optional","files":[{"name":"Code.gs","source":"..."}]}\n- {"action":"write_files","scriptId":"optional","files":[{"name":"Code.gs|Index.html|appsscript.json","source":"full source"}],"reply":"summary"}\n- {"action":"create_version","scriptId":"optional","description":"..."}\nWhen asked to build or modify code, output complete production-ready source for every file you change. Preserve existing functions unless user explicitly asks to replace them. If current project source is provided, base edits on it. Do not invent script IDs; use selectedScriptId by leaving scriptId empty when appropriate.`;
  const userPayload={message,selectedScriptId:scriptId||null,currentProject:context||null};
  const url=`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(key)}`;
  const r=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({systemInstruction:{parts:[{text:sys}]},contents:[{role:'user',parts:[{text:JSON.stringify(userPayload)}]}],generationConfig:{temperature:0.2,responseMimeType:'application/json'}})});
  const data=await r.json();
  if(!r.ok) throw new Error(data?.error?.message||`Gemini HTTP ${r.status}`);
  const text=(data.candidates?.[0]?.content?.parts||[]).map(p=>p.text||'').join('');
  return extractJsonObject(text);
}
app.post('/api/admin/chat',requireWebAdmin,async(req,res)=>{
  try{
    const message=String(req.body.message||'').trim();
    if(!message) return res.status(400).json({ok:false,error:'message required'});
    const selectedScriptId=String(req.body.scriptId||'').trim();
    let context=null;
    if(selectedScriptId){
      try{context=await webGetProjectContent(selectedScriptId);}catch(e){context={error:String(e.message||e)};}
    }
    const plan=await callGeminiPlanner({message,scriptId:selectedScriptId,context});
    let result=null;
    if(plan.action==='reply') result={reply:plan.reply||''};
    else if(plan.action==='list_projects') result={projects:await webFindProjects(plan.query||'')};
    else if(plan.action==='read_project') result=await webGetProjectContent(plan.scriptId||selectedScriptId);
    else if(plan.action==='create_project'){
      const requestBody={title:String(plan.title||'New Apps Script Project')}; if(plan.parentId)requestBody.parentId=String(plan.parentId);
      const cr=await scriptApi().projects.create({requestBody});
      result={project:cr.data};
      if(Array.isArray(plan.files)&&plan.files.length){
        if(scriptAccessMode()!=='all') throw new Error(`Project created (${cr.data.scriptId}) but SCRIPT_ACCESS_MODE is locked. Set SCRIPT_ACCESS_MODE=all or allow this ID before writing.`);
        result.write=await webWriteFiles(cr.data.scriptId,plan.files,{backup:false});
      }
    } else if(plan.action==='write_files'){
      const id=plan.scriptId||selectedScriptId;
      if(!id) throw new Error('Select a project first');
      result=await webWriteFiles(id,plan.files||[],{backup:true});
      result.reply=plan.reply||'บันทึกไฟล์เรียบร้อย';
    } else if(plan.action==='create_version'){
      const id=webResolveScriptId(plan.scriptId||selectedScriptId);
      const vr=await scriptApi().projects.versions.create({scriptId:id,requestBody:{description:String(plan.description||'Created from Web Tool Chat')}});
      result={version:vr.data};
    } else throw new Error(`Unsupported AI action: ${plan.action}`);
    res.json({ok:true,plan,result});
  }catch(e){
    console.error('[WEB CHAT ERROR]',String(e.message||e));
    res.status(500).json({ok:false,error:String(e.message||e)});
  }
});

app.get('/health',async(_req,res)=>{
  try{
    const sparkReady=!!(BASE&&process.env.SPARK_OAUTH_CLIENT_ID&&process.env.SPARK_OAUTH_CLIENT_SECRET&&process.env.SPARK_REDIRECT_URI&&process.env.SPARK_TOKEN_SIGNING_SECRET);
    if(!process.env.GOOGLE_REFRESH_TOKEN) return res.json({ok:false,googleOauthConfigured:false,sparkOauthConfigured:sparkReady});
    const t=await oauthClient().getAccessToken();
    res.json({ok:!!t.token,googleOauthConfigured:true,sparkOauthConfigured:sparkReady});
  }catch(e){res.status(500).json({ok:false,error:String(e.message||e)});}
});
app.get('/',(_req,res)=>res.json({ok:true,service:'apps-script-sheets-shopee-mcp',version:'4.5.0',sparkOAuth:true,mobileDefaults:true}));

function parseCommission(data,targetDate){
  const h=data.headers;
  const c={
    orderId:findIndex(h,['รหัสการสั่งซื้อ','Order ID','Order Id']),
    status:findIndex(h,['สถานะการสั่งซื้อ','Order Status']),
    purchaseTime:findIndex(h,['เวลาที่สั่งซื้อ','Purchase Time','เวลาสั่งซื้อ']),
    successTime:findIndex(h,['เวลาที่สั่งซื้อสำเร็จ','Order Completed Time','เวลาสำเร็จ'],false),
    clickTime:findIndex(h,['เวลาคลิก','Click Time'],false),
    sales:findIndex(h,['มูลค่าซื้อ(฿)','ยอดขาย(฿)','Sales','Order Amount']),
    comm:findIndex(h,['ค่าคอมมิชชั่นสุทธิ(฿)','ค่าคอมสุทธิ(฿)','Commission','Net Commission']),
    distrib:findIndex(h,['ประเภทการแจกจ่าย','Distribution Type'],false),
    sub:findIndex(h,['Sub_id1','Sub_id','Sub ID','SubId'],false),
    channel:findIndex(h,['ช่องทาง','Channel'],false),
    content:findIndex(h,['Content Type','ประเภทคอนเทนต์'],false)
  };
  const validStatuses=['สำเร็จ','รอดำเนินการ','Completed','Pending'];
  const dayRows=data.rows.filter(r=>validStatuses.includes(String(r[c.status]??'').trim()) && dateOnly(r[c.purchaseTime])===targetDate);
  const sales=sumRows(dayRows,c.sales), commission=sumRows(dayRows,c.comm), orders=uniqueCount(dayRows,c.orderId);

  const reels=dayRows.filter(r=>{
    const ch=c.channel>=0?String(r[c.channel]??'').trim():'';
    const ct=c.content>=0?String(r[c.content]??'').trim():'';
    return (!ch || ch==='Facebook') && (!ct || ct==='Facebook Reels');
  });

  const isDirect=r=>{
    if(c.distrib<0) return false;
    const x=String(r[c.distrib]??'').trim();
    return ['สั่งซื้อในร้านค้าเดียวกัน','Direct'].includes(x);
  };
  const isIndirect=r=>{
    if(c.distrib<0) return false;
    const x=String(r[c.distrib]??'').trim();
    return ['คำสั่งซื้อจากร้านค้าต่างกัน','Indirect'].includes(x);
  };

  const direct=sumRows(reels.filter(isDirect),c.comm);
  const indirect=sumRows(reels.filter(isIndirect),c.comm);

  const d0=c.clickTime>=0?reels.filter(r=>dateOnly(r[c.clickTime])===targetDate):[];
  const d0Orders=c.clickTime>=0?uniqueCount(d0,c.orderId):0;
  const d0Commission=c.clickTime>=0?sumRows(d0,c.comm):0;

  const successRows=(c.successTime>=0)?data.rows.filter(r=>{
    const st=String(r[c.status]??'').trim();
    return ['สำเร็จ','Completed'].includes(st) && dateOnly(r[c.successTime])===targetDate;
  }):[];

  const successfulSales=sumRows(successRows,c.sales);
  const successfulCommission=sumRows(successRows,c.comm);

  const pendingRows=data.rows.filter(r=>{
    const st=String(r[c.status]??'').trim();
    return ['รอดำเนินการ','Pending'].includes(st) && dateOnly(r[c.purchaseTime])===targetDate;
  });
  const pendingCommission=sumRows(pendingRows,c.comm);

  const bySub={};
  reels.forEach(r=>{
    const sub=c.sub>=0?normalizeSub(r[c.sub]):'(No SubID)';
    if(!bySub[sub]) bySub[sub]=[];
    bySub[sub].push(r);
  });
  const topSubs=Object.entries(bySub).map(([sub,rows])=>({
    sub,
    orders:uniqueCount(rows,c.orderId),
    sales:round2(sumRows(rows,c.sales)),
    commission:round2(sumRows(rows,c.comm)),
    directCommission:round2(sumRows(rows.filter(isDirect),c.comm)),
    indirectCommission:round2(sumRows(rows.filter(isIndirect),c.comm)),
    d0Orders:c.clickTime>=0?uniqueCount(rows.filter(r=>dateOnly(r[c.clickTime])===targetDate),c.orderId):0
  })).sort((a,b)=>b.commission-a.commission);

  const cohortMap={};
  if(c.clickTime>=0){
    reels.forEach(r=>{
      const cd=dateOnly(r[c.clickTime]); if(!cd) return;
      const lag=dayDiff(cd,targetDate);
      const key=`${cd}|${lag}`;
      if(!cohortMap[key]) cohortMap[key]=[];
      cohortMap[key].push(r);
    });
  }
  const cohort=Object.entries(cohortMap).map(([k,rows])=>{
    const [clickDate,lag]=k.split('|');
    return {
      purchaseDate:targetDate,clickDate,lagDay:Number(lag),
      orders:uniqueCount(rows,c.orderId),
      sales:round2(sumRows(rows,c.sales)),
      commission:round2(sumRows(rows,c.comm)),
      directCommission:round2(sumRows(rows.filter(isDirect),c.comm)),
      indirectCommission:round2(sumRows(rows.filter(isIndirect),c.comm))
    };
  }).sort((a,b)=>a.lagDay-b.lagDay);

  return {
    targetDate,sales:round2(sales),commission:round2(commission),orders,
    directCommission:round2(direct),indirectCommission:round2(indirect),
    d0Orders,d0Commission:round2(d0Commission),
    successfulSales:round2(successfulSales),
    successfulCommission:round2(successfulCommission),
    pendingCommission:round2(pendingCommission),
    topSubs,cohort
  };
}

function parseClicks(data,targetDate){
  const h=data.headers;
  const c={
    time:findIndex(h,['เวลาคลิก','Click Time']),
    region:findIndex(h,['ภาคที่คลิก','ประเทศที่คลิก','Region','Country'],false),
    sub:findIndex(h,['Sub_id','Sub ID','SubId','Sub_id1'],false),
    ref:findIndex(h,['อ้างอิง','อ้างอิqง','Referrer','Reference'],false)
  };
  const rows=data.rows.filter(r=>dateOnly(r[c.time])===targetDate);
  const bySub={};
  const byRegion={};
  const byRef={};
  rows.forEach(r=>{
    const sub=c.sub>=0?normalizeSub(r[c.sub]):'(No SubID)';
    bySub[sub]=(bySub[sub]||0)+1;
    if(c.region>=0){const x=String(r[c.region]??'').trim()||'(blank)';byRegion[x]=(byRegion[x]||0)+1;}
    if(c.ref>=0){const x=String(r[c.ref]??'').trim()||'(blank)';byRef[x]=(byRef[x]||0)+1;}
  });
  const top=(obj,n=20)=>Object.entries(obj).map(([name,value])=>({name,value})).sort((a,b)=>b.value-a.value).slice(0,n);
  return {targetDate,clicks:rows.length,topSubs:top(bySub),regions:top(byRegion),referrers:top(byRef)};
}

async function upsertDaily(spreadsheetId,sheetName,obj){
  assertAllowedSheet(spreadsheetId);
  const sheets=sheetsApi();
  const hdr=await sheets.spreadsheets.values.get({spreadsheetId,range:`'${sheetName}'!A1:Z1`});
  const headers=(hdr.data.values||[[]])[0];
  if(!headers.length) throw new Error(`No header row in sheet ${sheetName}`);

  const dates=await sheets.spreadsheets.values.get({spreadsheetId,range:`'${sheetName}'!A2:A2000`});
  const vals=(dates.data.values||[]);
  let row=vals.findIndex(r=>String(r[0]??'')===obj.Date);
  row=row>=0?row+2:vals.length+2;

  const out=headers.map(h=>obj[h]??'');
  await sheets.spreadsheets.values.update({
    spreadsheetId,range:`'${sheetName}'!A${row}:${String.fromCharCode(64+Math.min(headers.length,26))}${row}`,
    valueInputOption:'USER_ENTERED',requestBody:{values:[out]}
  });
  return row;
}

function makeServer(){
  const server=new McpServer({name:'google-apps-script-sheets-shopee-manager',version:'4.5.0'});

  // --- Apps Script full-control tools optimized for Spark/mobile ---
  // Security modes:
  // SCRIPT_ACCESS_MODE=locked (default): only ALLOWED_SCRIPT_ID / ALLOWED_SCRIPT_IDS.
  // SCRIPT_ACCESS_MODE=all: any Apps Script project accessible by the Google OAuth account.
  function resolveScriptId(inputId){
    const configured=(process.env.ALLOWED_SCRIPT_ID||'').trim();
    const resolved=(inputId||configured||'').trim();
    if(!resolved) throw new Error('No Apps Script project selected. Provide scriptId, set ALLOWED_SCRIPT_ID, or use apps_script_create_project first.');
    assertAllowedScript(resolved);
    return resolved;
  }
  function inferAppsScriptType(name,type){
    if(type) return type;
    const n=String(name||'').toLowerCase();
    if(n==='appsscript.json' || n.endsWith('.json')) return 'JSON';
    if(n.endsWith('.html')) return 'HTML';
    return 'SERVER_JS';
  }
  function normalizeScriptFileName(name){
    const n=String(name||'').trim();
    if(!n) throw new Error('File name is required');
    return n.replace(/\.(gs|html)$/i,'');
  }
  async function getProjectFiles(scriptId){
    const api=scriptApi();
    const r=await api.projects.getContent({scriptId});
    return r.data.files||[];
  }
  async function backupProject(scriptId,description){
    const api=scriptApi();
    const r=await api.projects.versions.create({scriptId,requestBody:{description:description||'MCP backup'}});
    return r.data.versionNumber;
  }

  server.registerTool('apps_script_create_project',{
    description:'CREATE a new Google Apps Script project directly. Use this whenever the user asks to create a new Apps Script project. parentId is optional; omit it for a standalone project, or provide a Google Sheet/Doc/Form Drive file ID to create a container-bound project when Google permits it. Returns the new scriptId.',
    inputSchema:{title:z.string().min(1),parentId:z.string().min(10).optional()}
  },async({title,parentId})=>{
    const requestBody={title}; if(parentId) requestBody.parentId=parentId;
    const r=await scriptApi().projects.create({requestBody});
    return {content:[{type:'text',text:JSON.stringify({ok:true,project:r.data,accessMode:scriptAccessMode(),note:'Use the returned scriptId for subsequent tools. If SCRIPT_ACCESS_MODE is locked, add this scriptId to ALLOWED_SCRIPT_IDS before editing it.'},null,2)}]};
  });

  server.registerTool('apps_script_get_content',{
    description:'READ all source files in an Apps Script project. If scriptId is omitted, uses ALLOWED_SCRIPT_ID. Returns exact current source so the model can inspect before editing.',
    inputSchema:{scriptId:z.string().min(10).optional()}
  },async({scriptId})=>{
    const resolvedScriptId=resolveScriptId(scriptId);
    const r=await scriptApi().projects.getContent({scriptId:resolvedScriptId});
    return {content:[{type:'text',text:JSON.stringify({scriptId:resolvedScriptId,files:r.data.files||[]},null,2)}]};
  });

  server.registerTool('apps_script_get_project',{
    description:'GET Apps Script project metadata such as title, scriptId, parentId and createTime/updateTime.',
    inputSchema:{scriptId:z.string().min(10).optional()}
  },async({scriptId})=>{
    const id=resolveScriptId(scriptId);
    const r=await scriptApi().projects.get({scriptId:id});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  server.registerTool('apps_script_write_file',{
    description:'CREATE or REPLACE one .gs, .html or appsscript.json file directly inside an Apps Script project. Preserves all other files and creates a backup version first. Use this tool instead of creating a Drive document when the user asks to write Apps Script code.',
    inputSchema:{scriptId:z.string().min(10).optional(),name:z.string().min(1),type:z.enum(['SERVER_JS','HTML','JSON']).optional(),source:z.string(),backup:z.boolean().optional()}
  },async({scriptId,name,type,source,backup})=>{
    const id=resolveScriptId(scriptId), api=scriptApi();
    const resolvedType=inferAppsScriptType(name,type), fileName=normalizeScriptFileName(name);
    const backupVersion=(backup===false)?null:await backupProject(id,`Backup before writing ${fileName}`);
    const files=await getProjectFiles(id);
    const i=files.findIndex(f=>f.name===fileName);
    const next={name:fileName,type:resolvedType,source};
    if(i>=0) files[i]=next; else files.push(next);
    await api.projects.updateContent({scriptId:id,requestBody:{files}});
    return {content:[{type:'text',text:JSON.stringify({ok:true,scriptId:id,file:fileName,type:resolvedType,created:i<0,replaced:i>=0,backupVersion},null,2)}]};
  });

  // Backward-compatible tool name retained for existing Spark configurations.
  server.registerTool('apps_script_update_file_safe',{
    description:'Safely CREATE or UPDATE one file in Apps Script directly. Equivalent to apps_script_write_file; preserves all other files and makes a backup version first.',
    inputSchema:{scriptId:z.string().min(10).optional(),name:z.string().min(1),type:z.enum(['SERVER_JS','HTML','JSON']).optional(),source:z.string()}
  },async({scriptId,name,type,source})=>{
    const id=resolveScriptId(scriptId), api=scriptApi();
    const resolvedType=inferAppsScriptType(name,type), fileName=normalizeScriptFileName(name);
    const backupVersion=await backupProject(id,`Backup before ${fileName}`);
    const files=await getProjectFiles(id); const i=files.findIndex(f=>f.name===fileName);
    const next={name:fileName,type:resolvedType,source}; if(i>=0) files[i]=next; else files.push(next);
    await api.projects.updateContent({scriptId:id,requestBody:{files}});
    return {content:[{type:'text',text:JSON.stringify({ok:true,scriptId:id,backupVersion,updatedFile:fileName,type:resolvedType,preservedOtherFiles:true},null,2)}]};
  });

  server.registerTool('apps_script_delete_file',{
    description:'DELETE one source file from an Apps Script project. Creates a backup version first and preserves all remaining files.',
    inputSchema:{scriptId:z.string().min(10).optional(),name:z.string().min(1)}
  },async({scriptId,name})=>{
    const id=resolveScriptId(scriptId), api=scriptApi(), fileName=normalizeScriptFileName(name);
    const backupVersion=await backupProject(id,`Backup before deleting ${fileName}`);
    const files=await getProjectFiles(id); const next=files.filter(f=>f.name!==fileName);
    if(next.length===files.length) throw new Error(`Apps Script file not found: ${fileName}`);
    if(next.length===0) throw new Error('Refusing to delete the final file in the project');
    await api.projects.updateContent({scriptId:id,requestBody:{files:next}});
    return {content:[{type:'text',text:JSON.stringify({ok:true,scriptId:id,deletedFile:fileName,backupVersion},null,2)}]};
  });

  server.registerTool('apps_script_rename_file',{
    description:'RENAME an Apps Script source file without changing its source. Creates a backup version first.',
    inputSchema:{scriptId:z.string().min(10).optional(),oldName:z.string().min(1),newName:z.string().min(1)}
  },async({scriptId,oldName,newName})=>{
    const id=resolveScriptId(scriptId), api=scriptApi();
    const oldN=normalizeScriptFileName(oldName), newN=normalizeScriptFileName(newName);
    const backupVersion=await backupProject(id,`Backup before renaming ${oldN} to ${newN}`);
    const files=await getProjectFiles(id);
    if(files.some(f=>f.name===newN)) throw new Error(`Target file already exists: ${newN}`);
    const f=files.find(x=>x.name===oldN); if(!f) throw new Error(`Apps Script file not found: ${oldN}`);
    f.name=newN; await api.projects.updateContent({scriptId:id,requestBody:{files}});
    return {content:[{type:'text',text:JSON.stringify({ok:true,scriptId:id,oldName:oldN,newName:newN,backupVersion},null,2)}]};
  });

  server.registerTool('apps_script_replace_project_content',{
    description:'REPLACE the entire Apps Script project content with the provided files. This can create/update/delete multiple files in one operation. A backup version is created first. Use only when the user explicitly wants a full-project rewrite.',
    inputSchema:{scriptId:z.string().min(10).optional(),files:z.array(z.object({name:z.string().min(1),type:z.enum(['SERVER_JS','HTML','JSON']).optional(),source:z.string()})).min(1)}
  },async({scriptId,files})=>{
    const id=resolveScriptId(scriptId), api=scriptApi();
    const backupVersion=await backupProject(id,'Backup before full project replacement');
    const normalized=files.map(f=>({name:normalizeScriptFileName(f.name),type:inferAppsScriptType(f.name,f.type),source:f.source}));
    await api.projects.updateContent({scriptId:id,requestBody:{files:normalized}});
    return {content:[{type:'text',text:JSON.stringify({ok:true,scriptId:id,replacedEntireProject:true,fileCount:normalized.length,backupVersion},null,2)}]};
  });

  server.registerTool('apps_script_create_version',{
    description:'CREATE an immutable Apps Script version from the current code.',
    inputSchema:{scriptId:z.string().min(10).optional(),description:z.string().optional()}
  },async({scriptId,description})=>{
    const id=resolveScriptId(scriptId);
    const r=await scriptApi().projects.versions.create({scriptId:id,requestBody:{description:description||'Created by MCP'}});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  server.registerTool('apps_script_list_versions',{
    description:'LIST Apps Script project versions.',
    inputSchema:{scriptId:z.string().min(10).optional(),pageSize:z.number().int().min(1).max(200).optional(),pageToken:z.string().optional()}
  },async({scriptId,pageSize,pageToken})=>{
    const id=resolveScriptId(scriptId);
    const r=await scriptApi().projects.versions.list({scriptId:id,pageSize:pageSize||50,pageToken});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  server.registerTool('apps_script_list_deployments',{
    description:'LIST deployments for an Apps Script project.',
    inputSchema:{scriptId:z.string().min(10).optional(),pageSize:z.number().int().min(1).max(200).optional(),pageToken:z.string().optional()}
  },async({scriptId,pageSize,pageToken})=>{
    const id=resolveScriptId(scriptId);
    const r=await scriptApi().projects.deployments.list({scriptId:id,pageSize:pageSize||50,pageToken});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  server.registerTool('apps_script_create_deployment',{
    description:'CREATE a deployment for an Apps Script version. versionNumber must already exist.',
    inputSchema:{scriptId:z.string().min(10).optional(),versionNumber:z.number().int().positive(),description:z.string().optional(),manifestFileName:z.string().optional()}
  },async({scriptId,versionNumber,description,manifestFileName})=>{
    const id=resolveScriptId(scriptId);
    const requestBody={versionNumber,description:description||'Created by MCP'};
    if(manifestFileName) requestBody.manifestFileName=manifestFileName;
    const r=await scriptApi().projects.deployments.create({scriptId:id,requestBody});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  server.registerTool('apps_script_update_deployment',{
    description:'UPDATE an existing Apps Script deployment to a different version/description.',
    inputSchema:{scriptId:z.string().min(10).optional(),deploymentId:z.string().min(1),versionNumber:z.number().int().positive(),description:z.string().optional(),manifestFileName:z.string().optional()}
  },async({scriptId,deploymentId,versionNumber,description,manifestFileName})=>{
    const id=resolveScriptId(scriptId);
    const requestBody={versionNumber}; if(description!==undefined) requestBody.description=description; if(manifestFileName) requestBody.manifestFileName=manifestFileName;
    const r=await scriptApi().projects.deployments.update({scriptId:id,deploymentId,requestBody});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  server.registerTool('apps_script_delete_deployment',{
    description:'DELETE an Apps Script deployment. This does not delete project source code.',
    inputSchema:{scriptId:z.string().min(10).optional(),deploymentId:z.string().min(1)}
  },async({scriptId,deploymentId})=>{
    const id=resolveScriptId(scriptId);
    await scriptApi().projects.deployments.delete({scriptId:id,deploymentId});
    return {content:[{type:'text',text:JSON.stringify({ok:true,scriptId:id,deletedDeploymentId:deploymentId},null,2)}]};
  });

  server.registerTool('apps_script_list_processes',{
    description:'LIST recent executions/processes for an Apps Script project for debugging and monitoring.',
    inputSchema:{scriptId:z.string().min(10).optional(),pageSize:z.number().int().min(1).max(50).optional(),pageToken:z.string().optional()}
  },async({scriptId,pageSize,pageToken})=>{
    const id=resolveScriptId(scriptId);
    const r=await scriptApi().processes.listScriptProcesses({scriptId:id,pageSize:pageSize||50,pageToken});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  server.registerTool('apps_script_find_projects',{
    description:'SEARCH Google Drive for Apps Script project files accessible to the connected Google account. Useful for discovering script IDs before editing. Does not modify anything.',
    inputSchema:{nameContains:z.string().optional(),pageSize:z.number().int().min(1).max(100).optional()}
  },async({nameContains,pageSize})=>{
    const clauses=["mimeType='application/vnd.google-apps.script'","trashed=false"];
    if(nameContains){ const safe=String(nameContains).replace(/'/g,"\\'"); clauses.push(`name contains '${safe}'`); }
    const r=await driveApi().files.list({q:clauses.join(' and '),pageSize:pageSize||50,fields:'files(id,name,mimeType,modifiedTime,createdTime,webViewLink,parents)'});
    return {content:[{type:'text',text:JSON.stringify({files:r.data.files||[]},null,2)}]};
  });

  server.registerTool('sheets_get_range',{
    description:'Read Google Sheet range.',
    inputSchema:{spreadsheetId:z.string().min(10),range:z.string().min(1)}
  },async({spreadsheetId,range})=>{
    assertAllowedSheet(spreadsheetId);
    const r=await sheetsApi().spreadsheets.values.get({spreadsheetId,range});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  server.registerTool('sheets_update_range',{
    description:'Write values into Google Sheet range.',
    inputSchema:{spreadsheetId:z.string().min(10),range:z.string().min(1),values:z.array(z.array(z.any()))}
  },async({spreadsheetId,range,values})=>{
    assertAllowedSheet(spreadsheetId);
    const r=await sheetsApi().spreadsheets.values.update({spreadsheetId,range,valueInputOption:'USER_ENTERED',requestBody:{values}});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  server.registerTool('drive_search_files',{
    description:'Search Drive files read-only.',
    inputSchema:{q:z.string().min(1),pageSize:z.number().int().min(1).max(100).optional()}
  },async({q,pageSize})=>{
    const r=await driveApi().files.list({q,pageSize:pageSize||50,fields:'files(id,name,mimeType,modifiedTime,size,webViewLink,parents)'});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  // --- NEW CSV tools ---
  server.registerTool('drive_read_csv',{
    description:'Download and parse a CSV file stored in Google Drive. Returns headers and up to maxRows rows.',
    inputSchema:{fileId:z.string().min(10),maxRows:z.number().int().min(1).max(5000).optional()}
  },async({fileId,maxRows})=>{
    const d=await parseCsvDrive(fileId);
    const n=maxRows||200;
    return {content:[{type:'text',text:JSON.stringify({headers:d.headers,rowCount:d.rows.length,rows:d.rows.slice(0,n)},null,2)}]};
  });

  server.registerTool('shopee_find_latest_reports',{
    description:'Find latest Shopee commission and click CSV files in a Drive folder.',
    inputSchema:{folderId:z.string().min(10).optional()}
  },async({folderId})=>{
    const fid=folderId||process.env.SHOPEE_FOLDER_ID;
    if(!fid) throw new Error('folderId or SHOPEE_FOLDER_ID required');
    const commission=await findLatestInFolder(fid,'AffiliateCommissionReport_');
    const clicks=await findLatestInFolder(fid,'WebsiteClickReport');
    return {content:[{type:'text',text:JSON.stringify({commission,clicks},null,2)}]};
  });

  server.registerTool('shopee_parse_commission_csv',{
    description:'Parse a Shopee Affiliate commission CSV from Drive and summarize one purchase date, including Direct/Indirect, D0, successful/pending, Top SubID and click cohorts.',
    inputSchema:{fileId:z.string().min(10),date:z.string().regex(/^\d{4}-\d{2}-\d{2}$/)}
  },async({fileId,date})=>{
    const d=await parseCsvDrive(fileId);
    return {content:[{type:'text',text:JSON.stringify(parseCommission(d,date),null,2)}]};
  });

  server.registerTool('shopee_parse_click_csv',{
    description:'Parse a Shopee WebsiteClickReport CSV from Drive for one date and summarize clicks, SubIDs, regions and referrers.',
    inputSchema:{fileId:z.string().min(10),date:z.string().regex(/^\d{4}-\d{2}-\d{2}$/)}
  },async({fileId,date})=>{
    const d=await parseCsvDrive(fileId);
    return {content:[{type:'text',text:JSON.stringify(parseClicks(d,date),null,2)}]};
  });

  server.registerTool('shopee_refresh_daily_report',{
    description:'End-to-end Shopee refresh: find latest commission/click CSVs in Drive, parse the specified date, calculate KPIs, and upsert the Daily Report Google Sheet.',
    inputSchema:{
      date:z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
      folderId:z.string().min(10).optional(),
      spreadsheetId:z.string().min(10).optional(),
      dailySheetName:z.string().optional()
    }
  },async({date,folderId,spreadsheetId,dailySheetName})=>{
    const fid=folderId||process.env.SHOPEE_FOLDER_ID;
    const sid=spreadsheetId||process.env.REPORT_SPREADSHEET_ID||process.env.ALLOWED_SPREADSHEET_ID;
    const sh=dailySheetName||process.env.REPORT_DAILY_SHEET||'Daily Report';
    if(!fid) throw new Error('Missing Shopee folder ID');
    if(!sid) throw new Error('Missing report spreadsheet ID');
    assertAllowedSheet(sid);

    const commFile=await findLatestInFolder(fid,'AffiliateCommissionReport_');
    const clickFile=await findLatestInFolder(fid,'WebsiteClickReport');
    if(!commFile||!clickFile) throw new Error('Latest commission/click report not found');

    const [commData,clickData]=await Promise.all([parseCsvDrive(commFile.id),parseCsvDrive(clickFile.id)]);
    const comm=parseCommission(commData,date);
    const clk=parseClicks(clickData,date);

    const d0Cvr=clk.clicks?comm.d0Orders/clk.clicks*100:0;
    const per1k=clk.clicks?comm.commission/clk.clicks*1000:0;

    const obj={
      Date:date,
      Sales:comm.sales,
      Commission:comm.commission,
      Clicks:clk.clicks,
      Orders:comm.orders,
      'Direct Commission':comm.directCommission,
      'Indirect Commission':comm.indirectCommission,
      'D0 Orders':comm.d0Orders,
      'D0 CVR %':round2(d0Cvr),
      'Comm / 1K Clicks':round2(per1k),
      'Successful Sales':comm.successfulSales,
      'Successful Commission':comm.successfulCommission,
      'Pending Commission':comm.pendingCommission,
      'Daily Insight':`Clicks ${clk.clicks.toLocaleString()} | D0 CVR ${round2(d0Cvr)}% | Comm/1K ${round2(per1k)}`
    };

    const row=await upsertDaily(sid,sh,obj);

    return {content:[{type:'text',text:JSON.stringify({
      ok:true,date,row,
      sourceFiles:{commission:commFile,clicks:clickFile},
      daily:obj,
      topCommissionSubIds:comm.topSubs.slice(0,10),
      topClickSubIds:clk.topSubs.slice(0,10),
      cohort:comm.cohort
    },null,2)}]};
  });

  return server;
}

async function handleMcp(req,res){
  try{
    const sid=req.get('mcp-session-id');
    let t=sid?sessions.get(sid):null;
    if(!t){
      const s=makeServer();
      t=new StreamableHTTPServerTransport({sessionIdGenerator:()=>randomUUID(),onsessioninitialized:id=>sessions.set(id,t)});
      t.onclose=()=>{if(t.sessionId)sessions.delete(t.sessionId)};
      await s.connect(t);
    }
    await t.handleRequest(req,res,req.body);
  }catch(e){
    console.error(e);
    if(!res.headersSent) res.status(500).json({error:String(e.message||e)});
  }
}
app.post('/mcp',requireMcpAuth,handleMcp);
app.get('/mcp',requireMcpAuth,handleMcp);
app.delete('/mcp',requireMcpAuth,handleMcp);

const port=Number(process.env.PORT||10000);
app.listen(port,'0.0.0.0',()=>console.log(`Server listening on ${port}`));
