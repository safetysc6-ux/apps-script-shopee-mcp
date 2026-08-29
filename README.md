# Apps Script + Sheets + Shopee CSV MCP v3

เวอร์ชันนี้เพิ่ม Shopee CSV โดยตรง

## Tool ใหม่
- `drive_read_csv`
- `shopee_find_latest_reports`
- `shopee_parse_commission_csv`
- `shopee_parse_click_csv`
- `shopee_refresh_daily_report`

## Flow ที่ทำได้
Shopee CSV -> Google Drive -> MCP -> Parse -> KPI -> Google Sheet -> Apps Script/Web Dashboard

ตัวอย่างคำสั่งกับ AI:
- "หาไฟล์ Shopee ล่าสุดในโฟลเดอร์แล้วสรุปวันที่ 28"
- "อ่าน WebsiteClickReport วันที่ 28 และหา Top SubID"
- "อ่าน Commission วันที่ 28 แยก Direct/Indirect/D0/Cookie"
- "อัปเดต Daily Report วันที่ 28 จากไฟล์ล่าสุดให้เลย"

## Render Environment ที่แนะนำ
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
GOOGLE_REDIRECT_URI=https://YOUR-SERVICE.onrender.com/oauth2callback
GOOGLE_REFRESH_TOKEN
ALLOWED_SCRIPT_ID
ALLOWED_SPREADSHEET_ID
SHOPEE_FOLDER_ID
REPORT_SPREADSHEET_ID
REPORT_DAILY_SHEET=Daily Report
MCP_BEARER_TOKEN
PORT=10000

## OAuth scopes
- script.projects
- script.deployments
- script.processes
- spreadsheets
- drive.readonly

## หมายเหตุ CSV
- รองรับ UTF-8/BOM
- รองรับหัวคอลัมน์ไทย/อังกฤษที่พบบ่อย
- normalize Sub ID ที่ลงท้ายด้วย ----
- รองรับไฟล์ขนาดหลาย MB โดยดาวน์โหลดจาก Drive แล้ว parse ฝั่ง server
