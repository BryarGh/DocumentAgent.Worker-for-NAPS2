# DocumentAgent Windows Service — Install / Uninstall
#
# ── FOR END USERS (no source code / no SDK needed) ──────────────────────────
#   1. Copy DocumentAgent.Worker.exe and this script into the same folder
#      (e.g. D:\DocumentAgent\)
#   2. Right-click PowerShell → Run as Administrator
#   3. cd to that folder, then:  .\install-service.ps1
#
# ── FOR DEVELOPERS (building from source) ───────────────────────────────────
#   Run from the project root (where .csproj lives):
#   .\install-service.ps1          — publishes then installs
#   .\install-service.ps1 -Publish — only publishes to .\publish\, does not install
#
# ── UNINSTALL ────────────────────────────────────────────────────────────────
#   .\install-service.ps1 -Uninstall

param(
    [switch]$Uninstall,
    [switch]$Publish   # developer-only: publish without installing
)

$ServiceName    = "DocumentAgent"
$ServiceDisplay = "Document Agent (NAPS2 Scanner)"
$ServiceDesc    = "Loopback scanning agent that drives NAPS2 and uploads scanned PDFs to your Laravel server."

# ── Require Administrator ────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as Administrator (right-click PowerShell → Run as Administrator)."
    exit 1
}

# ── Uninstall ────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Host "Stopping service '$ServiceName'..."
    sc.exe stop $ServiceName 2>$null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName 2>$null
    Write-Host "Service '$ServiceName' removed."
    exit 0
}

# ── Locate the exe ───────────────────────────────────────────────────────────
# Mode A: exe sits next to this script (end-user distribution)
$ExeNextToScript = Join-Path $PSScriptRoot "DocumentAgent.Worker.exe"

# Mode B: running from source — publish first, exe lands in .\publish\
$CsprojPath   = Join-Path $PSScriptRoot "DocumentAgent.Worker.csproj"
$PublishDir   = Join-Path $PSScriptRoot "publish"
$ExePublished = Join-Path $PublishDir "DocumentAgent.Worker.exe"

if (Test-Path $ExeNextToScript) {
    # ── End-user mode: exe already here, install directly ───────────────────
    $ExePath = $ExeNextToScript
    Write-Host "Found exe next to script — installing directly (no build needed)."

} elseif (Test-Path $CsprojPath) {
    # ── Developer mode: publish from source ─────────────────────────────────
    Write-Host "Publishing self-contained Windows executable (this takes ~30 s)..."
    dotnet publish "$CsprojPath" `
        --configuration Release `
        --runtime win-x64 `
        --self-contained true `
        --output "$PublishDir" `
        /p:PublishSingleFile=true `
        /p:IncludeNativeLibrariesForSelfExtract=true

    if ($LASTEXITCODE -ne 0) {
        Write-Error "dotnet publish failed. Fix build errors and try again."
        exit 1
    }

    $ExePath = $ExePublished

    if ($Publish) {
        Write-Host ""
        Write-Host "Published to: $PublishDir"
        Write-Host "Copy DocumentAgent.Worker.exe and install-service.ps1 to each laptop, then run the script as Administrator."
        exit 0
    }

} else {
    Write-Error @"
Cannot find DocumentAgent.Worker.exe or DocumentAgent.Worker.csproj next to this script.

End-user setup:
  Place DocumentAgent.Worker.exe in the same folder as this script, then re-run.

Developer setup:
  Run this script from the project folder that contains DocumentAgent.Worker.csproj.
"@
    exit 1
}

if (-not (Test-Path $ExePath)) {
    Write-Error "Exe not found at: $ExePath"
    exit 1
}

# ── Remove existing service if present ──────────────────────────────────────
sc.exe query $ServiceName 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Existing service found — stopping and removing..."
    sc.exe stop $ServiceName 2>$null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName
    Start-Sleep -Seconds 1
}

# ── Install and start ────────────────────────────────────────────────────────
Write-Host "Installing Windows Service '$ServiceName'..."
sc.exe create $ServiceName `
    binPath= "`"$ExePath`"" `
    DisplayName= "$ServiceDisplay" `
    start= auto

sc.exe description $ServiceName "$ServiceDesc"

# Auto-restart on failure: 3 attempts, 60 s delay each, reset counter after 24 h
sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000

Write-Host "Starting service..."
sc.exe start $ServiceName
Start-Sleep -Seconds 3
sc.exe query $ServiceName

$ConfigPath = "$env:USERPROFILE\Documents\DocumentAgent\agent.config.json"
$LogPath    = "$env:USERPROFILE\Documents\DocumentAgent\logs"

Write-Host ""
Write-Host "=========================================="
Write-Host " DocumentAgent installed successfully"
Write-Host "=========================================="
Write-Host " Exe:     $ExePath"
Write-Host " Config:  $ConfigPath"
Write-Host " Logs:    $LogPath"
Write-Host ""

if (-not (Test-Path $ConfigPath)) {
    Write-Host "NEXT STEP: Create the config file at:"
    Write-Host "  $ConfigPath"
    Write-Host ""
    Write-Host "Example content:"
    Write-Host '{
  "naps2_path": "C:\\Program Files\\NAPS2\\NAPS2.Console.exe",
  "upload_url": "http://192.168.33.50/api/document-agent/upload",
  "agent_token": "YOUR_TOKEN",
  "laravel_origin": "http://192.168.33.50"
}'
    Write-Host ""
    Write-Host "Then restart the service:  sc.exe restart DocumentAgent"
} else {
    Write-Host "Config file already exists — service is ready."
}

Write-Host ""
Write-Host "To uninstall:  .\install-service.ps1 -Uninstall"
