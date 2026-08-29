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

export function assertAllowedScript(id){
  const a=(process.env.ALLOWED_SCRIPT_ID||'').trim();
  if(a && id!==a) throw new Error('Script ID not allowed by server policy');
}
export function assertAllowedSheet(id){
  const a=(process.env.ALLOWED_SPREADSHEET_ID||'').trim();
  if(a && id!==a) throw new Error('Spreadsheet ID not allowed by server policy');
}
