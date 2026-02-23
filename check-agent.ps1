<#
Simple diagnostic helper for DocumentAgent on Windows.
Run in an elevated PowerShell (Run as Administrator) and paste the output here.
#>

Write-Host "=== DocumentAgent quick-check ===" -ForegroundColor Cyan

# 1) Service status
Write-Host "\n-- Service status --" -ForegroundColor Yellow
$svc = Get-Service -Name DocumentAgent -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Host "Service 'DocumentAgent' not found." -ForegroundColor Red
} else {
    Write-Host "Service: $($svc.Name)  Status: $($svc.Status)  StartType: $($svc.StartType)"
}

# 2) Latest log tail
$logDir = "$env:USERPROFILE\Documents\DocumentAgent\logs"
Write-Host "\n-- Latest log (if present) --" -ForegroundColor Yellow
if (-Not (Test-Path $logDir)) {
    Write-Host "Log folder not found: $logDir" -ForegroundColor Red
} else {
    $latest = Get-ChildItem -Path $logDir -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($null -eq $latest) {
        Write-Host "No log files found in: $logDir" -ForegroundColor Red
    } else {
        Write-Host "Latest log: $($latest.FullName) (LastWrite: $($latest.LastWriteTime))"
        Write-Host "--- tail (last 200 lines) ---"
        try { Get-Content -Path $latest.FullName -Tail 200 -ErrorAction Stop } catch { Write-Host "Failed to read log: $_" -ForegroundColor Red }
    }
}

# 3) agent.config.json and NAPS2 path
$configPath = "$env:USERPROFILE\Documents\DocumentAgent\agent.config.json"
Write-Host "\n-- agent.config.json --" -ForegroundColor Yellow
if (-Not (Test-Path $configPath)) {
    Write-Host "Config not found at: $configPath" -ForegroundColor Red
    Write-Host "Create the file and include 'naps2_path' pointing to your NAPS2.Console.exe"
} else {
    try {
        $json = Get-Content $configPath -Raw | Out-String
        Write-Host "Config contents:"; Write-Host $json
        $cfg = $json | ConvertFrom-Json -ErrorAction Stop
        $npath = $cfg.naps2_path
        if ($null -eq $npath -or $npath -eq '') { Write-Host "naps2_path not set in config." -ForegroundColor Red }
        else {
            Write-Host "naps2_path: $npath"
            Write-Host "Test-Path: " -NoNewline
            Write-Host (Test-Path $npath)

            # Try listdevices (twain + wia)
            Write-Host "\n-- Running NAPS2 listdevices (twain) --" -ForegroundColor Yellow
            try {
                & "$npath" --listdevices --driver twain 2>&1 | ForEach-Object { Write-Host $_ }
            } catch { Write-Host "Failed to run NAPS2 (twain): $_" -ForegroundColor Red }

            Write-Host "\n-- Running NAPS2 listdevices (wia) --" -ForegroundColor Yellow
            try {
                & "$npath" --listdevices --driver wia 2>&1 | ForEach-Object { Write-Host $_ }
            } catch { Write-Host "Failed to run NAPS2 (wia): $_" -ForegroundColor Red }
        }
    } catch { Write-Host "Failed to parse config JSON: $_" -ForegroundColor Red }
}

# 4) Call agent endpoint
Write-Host "\n-- Call agent /scanners endpoint --" -ForegroundColor Yellow
try {
    $res = Invoke-RestMethod -Uri http://127.0.0.1:3333/scanners -Method GET -ErrorAction Stop
    Write-Host ($res | ConvertTo-Json -Depth 5)
} catch { Write-Host "HTTP call failed: $_" -ForegroundColor Red }

# 5) Interactive-run suggestion
Write-Host "\n-- Interactive-run check --" -ForegroundColor Yellow
Write-Host "If the service is running but scanners are missing, try running the agent interactively (in your user session):"
Write-Host "1) Stop service: Stop-Service DocumentAgent -Force"
Write-Host "2) Run exe in your PowerShell: & 'C:\path\to\DocumentAgent.Worker.exe' (adjust path to your published exe)"
Write-Host "3) In another console, call: Invoke-RestMethod -Uri http://127.0.0.1:3333/scanners"
Write-Host "4) When finished, Ctrl+C the exe and Start-Service DocumentAgent"

Write-Host "\nDone. Paste any output here if you want me to inspect it." -ForegroundColor Cyan
