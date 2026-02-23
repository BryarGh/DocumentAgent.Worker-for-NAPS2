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
  "laravel_origin": "http://192.168.33.50"
}
```

**Windows** (point directly to `naps2.console.exe` — no `console` subcommand needed):

```json
{
  "naps2_path": "C:\\Program Files\\NAPS2\\naps2.console.exe",
  "upload_url": "https://your-app.test/api/document-agent/upload",
  "agent_token": "YOUR_TOKEN",
  "laravel_origin": "http://192.168.33.50"
}
```

## CORS / Allowed Origin

The agent reads `laravel_origin` from `agent.config.json` and uses it as the allowed CORS origin automatically — no extra environment variables needed. Set it to the address your users open in their browser (your Laravel server).

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
