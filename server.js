import 'dotenv/config';
import express from 'express';
import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { oauthClient,scriptApi,sheetsApi,driveApi,assertAllowedScript,assertAllowedSheet } from './google.js';
import {
  parseCsvDrive,findIndex,findLatestInFolder,dateOnly,num,normalizeSub,dayDiff,
  round2,uniqueCount,sumRows
} from './helpers.js';

const app=express();
app.use(express.json({limit:'16mb'}));
const sessions=new Map();

const OAUTH_SCOPES=[
  'https://www.googleapis.com/auth/script.projects',
  'https://www.googleapis.com/auth/script.deployments',
  'https://www.googleapis.com/auth/script.processes',
  'https://www.googleapis.com/auth/spreadsheets',
  'https://www.googleapis.com/auth/drive.readonly'
];

function requireBearer(req,res,next){
  const expected=(process.env.MCP_BEARER_TOKEN||'').trim();
  if(!expected) return next();
  if((req.get('authorization')||'')!==`Bearer ${expected}`) return res.status(401).json({error:'Unauthorized'});
  next();
}

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

app.get('/health',async(_req,res)=>{
  try{
    if(!process.env.GOOGLE_REFRESH_TOKEN) return res.json({ok:false,oauthConfigured:false});
    const t=await oauthClient().getAccessToken();
    res.json({ok:!!t.token,oauthConfigured:true});
  }catch(e){res.status(500).json({ok:false,error:String(e.message||e)});}
});
app.get('/',(_req,res)=>res.json({ok:true,service:'apps-script-sheets-shopee-mcp',version:'3.0.0'}));

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
  const server=new McpServer({name:'google-apps-script-sheets-shopee-manager',version:'3.0.0'});

  // --- Existing Apps Script / Sheets / Drive basics ---
  server.registerTool('apps_script_get_content',{
    description:'Read all source files from an Apps Script project.',
    inputSchema:{scriptId:z.string().min(10)}
  },async({scriptId})=>{
    assertAllowedScript(scriptId);
    const r=await scriptApi().projects.getContent({scriptId});
    return {content:[{type:'text',text:JSON.stringify(r.data,null,2)}]};
  });

  server.registerTool('apps_script_update_file_safe',{
    description:'Backup current HEAD, then update/add one Apps Script file while preserving all other files.',
    inputSchema:{scriptId:z.string().min(10),name:z.string().min(1),type:z.enum(['SERVER_JS','HTML','JSON']),source:z.string()}
  },async({scriptId,name,type,source})=>{
    assertAllowedScript(scriptId);
    const api=scriptApi();
    const backup=await api.projects.versions.create({scriptId,requestBody:{description:`Backup before ${name}`}});
    const cur=await api.projects.getContent({scriptId});
    const files=[...(cur.data.files||[])];
    const i=files.findIndex(f=>f.name===name);
    const next={name,type,source};
    if(i>=0) files[i]=next; else files.push(next);
    await api.projects.updateContent({scriptId,requestBody:{files}});
    return {content:[{type:'text',text:`Backup v${backup.data.versionNumber}; updated ${name}`}]};
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

app.post('/mcp',requireBearer,async(req,res)=>{
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
});

const port=Number(process.env.PORT||10000);
app.listen(port,'0.0.0.0',()=>console.log(`Server listening on ${port}`));
