# v4.2 Spark OAuth Debug Fix

Changes:
- Fixes missing `mintRefreshToken()` that could make `/oauth/token` return HTTP 500 after consent.
- Adds safe HTTP/OAuth/MCP request logging for Render Logs.
- Logs only route/status and boolean checks; it does **not** print bearer tokens, client secrets, authorization codes, refresh tokens, or query values.

After deploy, retry the Spark connection and inspect Render Logs for `[OAUTH ...]`, `[MCP AUTH]`, and `[HTTP]` lines.

---

# Apps Script + Sheets + Shopee MCP v4 — Spark OAuth

เพิ่ม OAuth สำหรับ **Spark → MCP** แยกจาก Google OAuth เดิม

## Render Environment ใหม่
```env
PUBLIC_BASE_URL=https://apps-script-shopee-mcp.onrender.com
SPARK_OAUTH_CLIENT_ID=ตั้งเอง เช่น spark-mcp-client
SPARK_OAUTH_CLIENT_SECRET=สุ่มยาวๆ
SPARK_REDIRECT_URI=คัดลอก URL การเปลี่ยนเส้นทางจาก Spark มาใส่ตรงนี้
SPARK_TOKEN_SIGNING_SECRET=สุ่มยาวอย่างน้อย 32 ตัวอักษร
```

> `SPARK_OAUTH_CLIENT_ID/SECRET` ไม่ใช่ Google OAuth Client ID/Secret

## ในหน้า Spark
- MCP URL: `https://apps-script-shopee-mcp.onrender.com/mcp`
- OAuth Client ID: ค่า `SPARK_OAUTH_CLIENT_ID`
- OAuth Client Secret: ค่า `SPARK_OAUTH_CLIENT_SECRET`
- กด “คัดลอก URL การเปลี่ยนเส้นทาง” แล้วนำไปใส่ Render เป็น `SPARK_REDIRECT_URI`

จากนั้น Save/Redeploy Render แล้วเชื่อมใหม่

## Health
`https://apps-script-shopee-mcp.onrender.com/health` ควรเห็น `googleOauthConfigured:true` และ `sparkOauthConfigured:true`

Google OAuth เดิม (`/auth/start`, `/oauth2callback`) ยังคงใช้สำหรับ MCP → Google API เหมือนเดิม
