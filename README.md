# Apps Script + Sheets + Shopee MCP v4.3 — Spark Mobile Fix

Version 4.3 keeps the Spark OAuth/debug fixes from v4.2 and makes Apps Script editing easier from Gemini/Spark on mobile.

## What changed in v4.3

- `apps_script_get_content` no longer requires `scriptId`.
- `apps_script_update_file_safe` no longer requires `scriptId`.
- Both tools automatically use `ALLOWED_SCRIPT_ID` from Render when `scriptId` is omitted.
- `type` is optional when updating a file:
  - `.html` -> `HTML`
  - `.json` / `appsscript.json` -> `JSON`
  - everything else -> `SERVER_JS`
- Every Apps Script update still creates a backup version first and preserves all other project files.
- Keeps v4.2 safe HTTP/OAuth/MCP debug logging without printing secrets/tokens.

## Required Render variable

Make sure this already exists:

```text
ALLOWED_SCRIPT_ID=<your Apps Script Script ID from Project Settings>
```

Do not paste the Script ID into Gemini prompts after this. The server resolves it automatically.

## Deploy

1. Extract this ZIP.
2. Upload/replace these files in the existing GitHub repository.
3. Commit.
4. Wait for Render auto-deploy.
5. Open the root URL and confirm `version` is `4.3.0`.
6. `/health` should still show both Google OAuth and Spark OAuth configured.
7. In Gemini/Spark, disconnect/reconnect the custom app if the old tool schema is cached.

## Example mobile prompts

Read code:

```text
อ่าน Apps Script ปัจจุบันของฉัน แล้วสรุปว่าแต่ละไฟล์ทำอะไร ยังไม่ต้องแก้ไข
```

Update Code.gs:

```text
อ่าน Apps Script ปัจจุบันก่อน แล้วแก้ Code.gs ให้เพิ่มฟังก์ชันสรุปยอดรายวัน โดยเก็บโค้ดเดิมและฟังก์ชันเดิมทั้งหมดไว้ จากนั้นบอกว่าปรับอะไรไปบ้าง
```

Create/update HTML:

```text
แก้ Index.html ใน Apps Script ให้เพิ่มปุ่ม Refresh โดยห้ามลบส่วนเดิม และสำรองเวอร์ชันก่อนแก้
```
