# DocumentAgent Windows Service installer
# Run once as Administrator:  .\install-service.ps1
# To uninstall:               .\install-service.ps1 -Uninstall

param(
    [switch]$Uninstall
)

$ServiceName  = "DocumentAgent"
$ServiceDisplay = "Document Agent (NAPS2 Scanner)"
$ServiceDesc  = "Loopback scanning agent that drives NAPS2 and uploads scanned PDFs to your Laravel server."
$ExePath      = Join-Path $PSScriptRoot "publish\DocumentAgent.Worker.exe"
$PublishDir   = Join-Path $PSScriptRoot "publish"

# ── Require Administrator ────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as Administrator."
    exit 1
}

# ── Uninstall ────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Host "Stopping and removing service '$ServiceName'..."
    sc.exe stop  $ServiceName 2>$null
    sc.exe delete $ServiceName 2>$null
    Write-Host "Done. Service removed."
    exit 0
}

# ── Publish self-contained exe ───────────────────────────────────────────────
Write-Host "Publishing self-contained Windows executable..."
dotnet publish "$PSScriptRoot\DocumentAgent.Worker.csproj" `
    --configuration Release `
    --runtime win-x64 `
    --self-contained true `
    --output "$PublishDir" `
    /p:PublishSingleFile=true `
    /p:IncludeNativeLibrariesForSelfExtract=true

if ($LASTEXITCODE -ne 0) {
    Write-Error "dotnet publish failed. Fix build errors first."
    exit 1
}

if (-not (Test-Path $ExePath)) {
    Write-Error "Expected exe not found at: $ExePath"
    exit 1
}

# ── Remove old service if it exists ─────────────────────────────────────────
$existing = sc.exe query $ServiceName 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Existing service found — stopping and removing..."
    sc.exe stop   $ServiceName 2>$null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName
    Start-Sleep -Seconds 1
}

# ── Create and start the service ────────────────────────────────────────────
Write-Host "Creating Windows Service '$ServiceName'..."
sc.exe create $ServiceName `
    binPath= "`"$ExePath`"" `
    DisplayName= "$ServiceDisplay" `
    start= auto

sc.exe description $ServiceName "$ServiceDesc"

# The service logs to ~/Documents/DocumentAgent/logs — no extra config needed.
Write-Host "Starting service..."
sc.exe start $ServiceName

Start-Sleep -Seconds 3
sc.exe query $ServiceName

Write-Host ""
Write-Host "Installation complete."
Write-Host "  Service: $ServiceName"
Write-Host "  Exe:     $ExePath"
Write-Host "  Logs:    $env:USERPROFILE\Documents\DocumentAgent\logs"
Write-Host "  Config:  $env:USERPROFILE\Documents\DocumentAgent\agent.config.json"
Write-Host ""
Write-Host "To uninstall later, run:  .\install-service.ps1 -Uninstall"
