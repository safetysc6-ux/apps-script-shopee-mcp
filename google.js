import 'dotenv/config';
import { google } from 'googleapis';

export function oauthClient() {
  const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, GOOGLE_REFRESH_TOKEN } = process.env;
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REDIRECT_URI) {
    throw new Error('Missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REDIRECT_URI');
  }
  const c = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
  if (GOOGLE_REFRESH_TOKEN) c.setCredentials({ refresh_token: GOOGLE_REFRESH_TOKEN });
  return c;
}
export function scriptApi(){ return google.script({version:'v1',auth:oauthClient()}); }
export function sheetsApi(){ return google.sheets({version:'v4',auth:oauthClient()}); }
export function driveApi(){ return google.drive({version:'v3',auth:oauthClient()}); }

function csvSet(v){ return new Set(String(v||'').split(',').map(x=>x.trim()).filter(Boolean)); }

export function scriptAccessMode(){
  return String(process.env.SCRIPT_ACCESS_MODE||'locked').trim().toLowerCase();
}
export function assertAllowedScript(id){
  const mode=scriptAccessMode();
  if(mode==='all') return;
  const allowed=csvSet(process.env.ALLOWED_SCRIPT_IDS||process.env.ALLOWED_SCRIPT_ID||'');
  if(allowed.size===0) throw new Error('No Apps Script project allowed. Set ALLOWED_SCRIPT_ID/ALLOWED_SCRIPT_IDS, or SCRIPT_ACCESS_MODE=all.');
  if(!allowed.has(id)) throw new Error('Script ID not allowed by server policy');
}
export function assertAllowedSheet(id){
  const mode=String(process.env.SHEET_ACCESS_MODE||'locked').trim().toLowerCase();
  if(mode==='all') return;
  const allowed=csvSet(process.env.ALLOWED_SPREADSHEET_IDS||process.env.ALLOWED_SPREADSHEET_ID||'');
  if(allowed.size && !allowed.has(id)) throw new Error('Spreadsheet ID not allowed by server policy');
}
