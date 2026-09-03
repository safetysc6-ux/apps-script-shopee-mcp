# Apps Script + Sheets + Shopee MCP v4.5 Web Tool

Adds a mobile-friendly Web Tool / Chat console on top of v4.4 Full Apps Script Control.

## New page

`https://YOUR-RENDER-SERVICE.onrender.com/tool`

Features:
- Beautiful responsive chat-style UI for mobile/desktop
- Apps Script project browser
- Read/edit/create `.gs`, `.html`, and `appsscript.json`
- Automatic backup version before code writes
- Create Apps Script projects
- Create versions and inspect deployments
- Optional Gemini-powered natural-language commands directly from the web page
- Existing MCP, Google OAuth, Sheets, Drive and Shopee tools remain available

## Required Render environment for Web Tool

```
WEB_ADMIN_TOKEN=<generate a long random secret>
```

Use that token to sign in to `/tool`.

For free-text AI chat also add:

```
GEMINI_API_KEY=<your Google AI Gemini API key>
GEMINI_MODEL=gemini-2.5-flash
```

If you want the Web Tool to manage any Apps Script project accessible to the connected Google account:

```
SCRIPT_ACCESS_MODE=all
```

Keep all existing OAuth/MCP/Sheets/Shopee environment variables from v4.4.

## Security

- Never expose `WEB_ADMIN_TOKEN`, `GEMINI_API_KEY`, Google refresh token, or Spark OAuth secrets.
- The web UI stores `WEB_ADMIN_TOKEN` in browser localStorage on the device used to sign in.
- Code writes create a backup Apps Script version first.
- `SCRIPT_ACCESS_MODE=all` is powerful: the server can modify any Apps Script project available to the authorized Google account.

## Deploy

1. Upload all files in this package over the existing GitHub repository.
2. Commit and let Render auto-deploy.
3. Add `WEB_ADMIN_TOKEN` in Render Environment.
4. Optional: add `GEMINI_API_KEY`.
5. Confirm `/` returns version `4.5.0`.
6. Open `/tool`.
