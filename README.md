# DocumentAgent.Worker for NAPS2

A .NET 8 minimal API + background worker that drives NAPS2 CLI for reliable document scanning on macOS/Linux/Windows. It exposes a loopback-only HTTP API used by the Laravel SDK companion: https://github.com/BryarGh/laravel-document-agent

## Features

- Scan acquisition via NAPS2 CLI with 10-minute timeout and process-tree kill safety (uses `console` subcommand on macOS/Linux; points directly to `naps2.console.exe` on Windows).
- Scanner discovery across drivers (`apple`, `sane`, `escl`).
- Disk-backed, crash-resilient job queue (queued → acquiring → processing → uploading → completed/failed).
- Uploads with SHA256 verification, exponential backoff, bearer token.
- Status/health endpoints with degraded detection and disk free reporting.

## Build & Run

```bash
# From src/DocumentAgent.Worker
dotnet restore
DOTNET_ENVIRONMENT=Production dotnet run
```

Agent data directories are under `~/Documents/DocumentAgent` by default (config, logs, queue, scanned files, cache).

## Configuration

`~/Documents/DocumentAgent/agent.config.json` example:

**macOS:**

```json
{
  "naps2_path": "/Applications/NAPS2.app/Contents/MacOS/NAPS2",
  "upload_url": "https://your-app.test/api/document-agent/upload",
  "agent_token": "YOUR_TOKEN",
  "laravel_origin": "http://192.168.33.50",
  "whatsapp_enabled": true,
  "whatsapp_credentials_source": "igms_with_fallback",
  "whatsapp_credentials_url": "https://your-app.test/api/document-agent/whatsapp/credentials",
  "whatsapp_credentials_ttl_seconds": 900,
  "whatsapp_max_retries": 5,
  "whatsapp_timeout_seconds": 30
}
```

**Windows** (point directly to `naps2.console.exe` — no `console` subcommand needed):

```json
{
  "naps2_path": "C:\\Program Files\\NAPS2\\naps2.console.exe",
  "upload_url": "https://your-app.test/api/document-agent/upload",
  "agent_token": "YOUR_TOKEN",
  "laravel_origin": "http://192.168.33.50",
  "whatsapp_enabled": true,
  "whatsapp_credentials_source": "igms_with_fallback",
  "whatsapp_credentials_url": "https://your-app.test/api/document-agent/whatsapp/credentials",
  "whatsapp_credentials_ttl_seconds": 900,
  "whatsapp_max_retries": 5,
  "whatsapp_timeout_seconds": 30
}
```

Optional local fallback keys (only for `igms_with_fallback` transition mode):

```json
{
  "twilio_account_sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "twilio_auth_token": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "twilio_whatsapp_from": "whatsapp:+14155238886"
}
```

## CORS / Allowed Origin

The agent reads `laravel_origin` from `agent.config.json` and uses it as the allowed CORS origin automatically — no extra environment variables needed. Set it to the address your users open in their browser (your Laravel server).

## WhatsApp Credential Source Modes

The worker supports centralized Twilio credentials from IGMS Settings with safe fallback:

- `whatsapp_credentials_source: "local"`
  - Uses only `twilio_account_sid`, `twilio_auth_token`, and `twilio_whatsapp_from` from local JSON.
- `whatsapp_credentials_source: "igms_with_fallback"` (recommended)
  - Fetches credentials from `whatsapp_credentials_url` using `agent_token` bearer auth.
  - Caches credentials in memory for `whatsapp_credentials_ttl_seconds`.
  - Falls back to local JSON credentials if IGMS is temporarily unreachable.
  - Local Twilio keys are optional and should be removed after confidence period if policy requires centralized-only secrets.
- `whatsapp_credentials_source: "igms"`
  - Uses IGMS credentials only, with no local fallback.

When credentials are fetched successfully from IGMS, the worker mirrors effective values into `agent.config.json` keys for operational continuity.

Fallback order:

1. `laravel_origin` in `agent.config.json` ← recommended
2. `AGENT_ALLOWED_ORIGIN` environment variable
3. `*` (allow all — development only)

The agent sends `Access-Control-Allow-Origin` headers on every response and handles `OPTIONS` preflight requests automatically.

## API Endpoints (loopback only)

- `GET /health` → `{ status, version, machine_uuid }`
- `GET /port` → `{ port }`
- `GET /status` → `{ scanner_connected, printer_connected, last_scan_time, queued_jobs, failed_jobs, degraded, disk_free_mb, agent_uptime_seconds, default_scanner_available, naps2_path }`
- `GET /scanners` → `{ profiles: [{ name }], default_available }`
- `GET /profiles` → `{ profiles: [...] }`
- `POST /profiles` → body `{ profile_name, scanner_name, dpi, color_mode, source, duplex, paper_size }`
- `POST /scan` → body `{ document_id, profile_name, client_request_id? }`; returns 202 `{ job_id, status, deduped? }`
- `GET /scan/{jobId}` → `{ job_id, status, error_message? }`
- `POST /send-whatsapp` → body `{ notification_id?, event_type?, phone_number, content, callback_url? }`; returns 202 `{ message_id, status }`
- `GET /whatsapp/{messageId}` → `{ message_id, status, provider_message_sid?, error_message?, error_code? }`

Errors include `scanner_unavailable`, `profile_not_found`, `upload_url_missing`, `scan_timeout`, `scan_failed`, `insufficient_disk_space`.

## Logs & Troubleshooting

- Logs: `~/Documents/DocumentAgent/logs/YYYY-MM-DD.log` (JSON lines)
- Scanned PDFs: `~/Documents/DocumentAgent/scanned/<jobId>/<jobId>.pdf`
- Cache of uploaded PDFs: `~/Documents/DocumentAgent/cache/completed`

## Relationship to Laravel package

Use the Laravel SDK (https://github.com/BryarGh/laravel-document-agent) to talk to this agent from your Laravel 10–12 / PHP 8.4+ app. The SDK handles port detection, profile management, scan start, polling, and error surfacing.

## Testing quickstart

```bash
curl http://127.0.0.1:3333/scanners
curl -X POST http://127.0.0.1:3333/profiles \
  -H "Content-Type: application/json" \
  -d '{"profile_name":"HomePrinter","scanner_name":"EPSON L3250 Series","dpi":300,"color_mode":"color","source":"ADF","duplex":false,"paper_size":"A4"}'

curl -X POST http://127.0.0.1:3333/scan \
  -H "Content-Type: application/json" \
  -d '{"document_id":"TEST-001","profile_name":"HomePrinter","client_request_id":"TEST-001"}'

curl http://127.0.0.1:3333/scan/<job_id>
```

## Windows quickstart & troubleshooting

Follow these steps on Windows machines to install and run the agent reliably, and use the troubleshooting tips when something fails.

### Recommended runtime mode for scanner stability

- You do **not** need to remove `install-service.ps1`.
- The installer now supports **both** modes:
  - default: Windows Service
  - optional: Startup Task at user logon via `-StartupTask`
- Reason: many TWAIN/WIA drivers require an interactive desktop session and can fail in Session 0 service context.

Install as a Windows Service:

```powershell
.\install-service.ps1
```

Install as a Startup Task (preferred for TWAIN/WIA scanners):

```powershell
.\install-service.ps1 -StartupTask
```

Publish only:

```powershell
.\install-service.ps1 -Publish
```

- Remove Service install:

```powershell
.\install-service.ps1 -Uninstall
```

- Remove Startup Task install:

```powershell
.\install-service.ps1 -StartupTask -Uninstall
```

### What is the difference?

- **Service mode** starts at Windows boot, even before user logon. Good for server-style always-on behavior.
- **Startup task mode** starts when the target user logs into Windows. Good for desktop scanners that need an interactive session.
- If manual EXE run works but service mode fails, startup task mode is the right choice.

### Will startup task mode start automatically?

- Yes. It starts automatically at that user's Windows logon.
- The installer also starts it immediately once, so you do not need to log out and back in after installation.

### How do I debug it later?

- For both modes:

```powershell
curl http://127.0.0.1:3333/health
curl http://127.0.0.1:3333/scanners
```

- Logs are still here in both modes:

```powershell
$env:USERPROFILE\Documents\DocumentAgent\logs
```

- Debug service mode:

```powershell
Get-Service DocumentAgent
sc.exe qc DocumentAgent
sc.exe queryex DocumentAgent
```

- Debug startup task mode:

```powershell
Get-ScheduledTask -TaskName "DocumentAgent-Startup"
Get-ScheduledTaskInfo -TaskName "DocumentAgent-Startup"
```

- If you want foreground debugging, run the EXE manually again from a normal logged-in session.

### How do I stop or turn it off temporarily?

- Stop service mode now:

```powershell
Stop-Service DocumentAgent
```

- Disable service mode from starting automatically:

```powershell
Set-Service DocumentAgent -StartupType Disabled
```

- Stop startup task mode now:

```powershell
Stop-Process -Name DocumentAgent.Worker -ErrorAction SilentlyContinue
```

- Disable startup task mode without uninstalling:

```powershell
Disable-ScheduledTask -TaskName "DocumentAgent-Startup"
```

- Re-enable startup task mode:

```powershell
Enable-ScheduledTask -TaskName "DocumentAgent-Startup"
Start-ScheduledTask -TaskName "DocumentAgent-Startup"
```

- Publish for distribution (developer machine):

```powershell
# run as Administrator from the project folder
.\install-service.ps1 -Publish
```

- End-user install (no SDK required): copy `DocumentAgent.Worker.exe` and `install-service.ps1` into the same folder on the laptop, open an elevated PowerShell, then run:

```powershell
# run as Administrator
.\install-service.ps1
```

- If PowerShell blocks the script (error: "cannot be loaded because running scripts is disabled"), the system execution policy is set to `Restricted`. Choose ONE of these solutions (all require Administrator):

**Solution 1: Temporary bypass (recommended for single use)**

```powershell
# Run from elevated PowerShell or CMD
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\install-service.ps1"
```

**Solution 2: Permanent policy change (recommended for ongoing use)**

```powershell
# OR change the policy permanently (elevated PowerShell)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
.\install-service.ps1
```

**Solution 3: Unblock file + bypass (only if file was downloaded)**

```powershell
# If the file came from the internet and has a Zone.Identifier attribute
Unblock-File -Path "C:\path\to\install-service.ps1"
# Then run with bypass (the unblock alone won't work if policy is Restricted)
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\install-service.ps1"
```

Reference: [PowerShell Execution Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)

- Common mistakes & fixes

- **Service installs/shows as Running but port is unreachable and nothing works**

  **Root cause:** Windows services run under the `LocalSystem` account. When it calls `Environment.GetFolderPath(MyDocuments)` it gets `C:\Windows\system32\config\systemprofile\Documents` — **not** your `C:\Users\<you>\Documents`. The agent starts but can't find `agent.config.json`, the log folder, the job queue, or the scan profiles, so it behaves as if it is unconfigured.

  **Fix (already applied in the current install script):** `install-service.ps1` writes the real user's path into the service's registry `Environment` block right after `sc.exe create`:

  ```
  HKLM\SYSTEM\CurrentControlSet\Services\DocumentAgent  →  Environment: DOCUMENTAGENT_BASE_PATH=C:\Users\<you>\Documents\DocumentAgent
  ```

  The agent reads this variable on startup and uses it as the base path for all data.

  **If you installed before this fix**, re-run the install script as Administrator (it will stop/delete the old service and reinstall with the correct environment). Or set the variable manually:

  ```powershell
  # Run as Administrator in PowerShell
  $docs = [Environment]::GetFolderPath("MyDocuments")
  $path = Join-Path $docs "DocumentAgent"
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DocumentAgent" `
      -Name "Environment" -Value @("DOCUMENTAGENT_BASE_PATH=$path") -Type MultiString
  Restart-Service DocumentAgent
  # Verify
  curl http://127.0.0.1:3333/health
  ```

- **Double PowerShell invocation error**
  - Error: `no : The term 'no' is not recognized ...` happens when you run `powershell powershell -NoProfile ...` inside an already opened PowerShell session. Either run the command from CMD or simply run the script directly from an elevated PowerShell prompt:

```powershell
# WRONG (causes parsing errors inside PowerShell):
powershell powershell -NoProfile -ExecutionPolicy Bypass -File .\install-service.ps1

# CORRECT from elevated PowerShell:
.\install-service.ps1

# OR from elevated CMD:
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\install-service.ps1"
```

- Service create/delete race (error 1072)
  - If you see `CreateService FAILED 1072: The specified service has been marked for deletion.`, Windows is still removing the old service. Wait a few seconds (or reboot) and retry the `sc create` command. Example manual install:

```powershell
sc create DocumentAgent binPath= "C:\Path\To\DocumentAgent.Worker.exe" start= auto DisplayName= "Document Agent"
sc description DocumentAgent "Loopback scanning agent that drives NAPS2 and uploads scanned PDFs to your Laravel server."
sc start DocumentAgent
```

- Verify service status and logs

```powershell
sc query DocumentAgent
Get-Service DocumentAgent
dir "$env:USERPROFILE\Documents\DocumentAgent\logs" | sort LastWriteTime -Descending | select -First 5
curl http://127.0.0.1:3333/scanners
```

- Built-in diagnostics on service start failure (recommended)
  - If `install-service.ps1` fails to start the service (for example error `1053`), it now prints a diagnostics block automatically, including:
  - `sc qc` (binary path and startup config)
  - `sc queryex` (runtime state / exit info)
  - Service registry `Environment` values (including `DOCUMENTAGENT_BASE_PATH`)
  - Executable metadata (exists/size/last write/SHA256)
  - Recent Service Control Manager + Application Event Log entries
  - Tail of the latest agent log file
  - When opening an issue, paste the entire `========= DocumentAgent Diagnostics =========` block. That usually gives enough evidence to identify root cause in one pass.

- agent.config.json notes
  - Path examples for Windows must escape backslashes or use forward slashes. Example valid JSON value:

```json
{
  "naps2_path": "C:\\Program Files\\NAPS2\\NAPS2.Console.exe",
  "upload_url": "https://your-app.test/api/document-agent/upload",
  "agent_token": "YOUR_TOKEN",
  "laravel_origin": "http://192.168.33.50"
}
```

- The agent auto-corrects common issues: unescaped backslashes and invisible Unicode characters inserted by copy/paste (U+202A etc). If the agent logs `Skipping scanner refresh — NAPS2 not found at path: ...`, check `agent.config.json` for hidden characters or extra whitespace.

- NAPS2 & drivers on Windows
  - Windows commonly uses `twain` and `wia` drivers. If `/scanners` returns empty, check that `naps2_path` points to the correct `NAPS2.Console.exe` and run that binary manually to confirm it lists devices:

```powershell
& "C:\Program Files\NAPS2\NAPS2.Console.exe" --listdevices --driver twain
```

- If `--listdevices` outputs scanner names but the agent still shows none, copy the exact `stdout` and `stderr` lines from the agent log and paste them into an issue — the logs now include full NAPS2 output to help debug.

- Antivirus / permissions
  - Windows Defender / AV software may block the published exe. If the agent fails to start or NAPS2 cannot access drivers, temporarily disable AV or add the agent folder to exclusions.

- Uninstall
  - To remove the service:

```powershell
.\install-service.ps1 -Uninstall
# or (manual)
sc stop DocumentAgent
sc delete DocumentAgent
```

If you want additional quickchecks to include in the README (e.g. Event Viewer queries, exact log examples), tell me which ones you prefer and I will add them.
