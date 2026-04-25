# DocumentAgent Windows Service -- Install / Uninstall
#
# -- FOR END USERS (no source code / no SDK needed) --------------------------
#   1. Copy DocumentAgent.Worker.exe and this script into the same folder
#      (e.g. D:\DocumentAgent\)
#   2. Right-click PowerShell -> Run as Administrator
#   3. cd to that folder, then:  .\install-service.ps1
#
# -- FOR DEVELOPERS (building from source) -----------------------------------
#   Run from the project root (where .csproj lives):
#   .\install-service.ps1          -- publishes then installs
#   .\install-service.ps1 -Publish -- only publishes to .\publish\, does not install
#
# -- UNINSTALL ----------------------------------------------------------------
#   .\install-service.ps1 -Uninstall

param(
    [switch]$Uninstall,
    [switch]$Publish   # developer-only: publish without installing
)

# Prevent silent script termination from non-terminating errors.
$ErrorActionPreference = 'Continue'

$PublishRequested = $PSBoundParameters.ContainsKey('Publish') -and $Publish.IsPresent

$ServiceName    = "DocumentAgent"
$ServiceDisplay = "Document Agent (NAPS2 Scanner)"
$ServiceDesc    = "Loopback scanning agent that drives NAPS2 and uploads scanned PDFs to your Laravel server."

function Show-ServiceDiagnostics {
    param(
        [string]$Name,
        [string]$ExePath,
        [string]$AgentBasePath
    )

    Write-Host ""
    Write-Host "========= DocumentAgent Diagnostics =========" -ForegroundColor Yellow

    Write-Host "[A] Service config (sc qc):" -ForegroundColor Cyan
    cmd /c "sc.exe qc $Name"

    Write-Host ""
    Write-Host "[B] Service runtime state (sc queryex):" -ForegroundColor Cyan
    cmd /c "sc.exe queryex $Name"

    Write-Host ""
    Write-Host "[C] Service registry Environment block:" -ForegroundColor Cyan
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        $envBlock = (Get-ItemProperty -Path $regPath -Name "Environment" -ErrorAction Stop).Environment
        if ($null -eq $envBlock -or $envBlock.Count -eq 0) {
            Write-Host "(empty)"
        } else {
            $envBlock | ForEach-Object { Write-Host "  $_" }
        }
    } catch {
        Write-Host "Unable to read Environment registry value: $_" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "[D] Exe path + file metadata:" -ForegroundColor Cyan
    Write-Host "  ExePath: $ExePath"
    if (Test-Path $ExePath) {
        try {
            $item = Get-Item $ExePath
            $hash = Get-FileHash -Path $ExePath -Algorithm SHA256
            Write-Host "  Exists: true"
            Write-Host "  Size: $($item.Length) bytes"
            Write-Host "  LastWrite: $($item.LastWriteTime)"
            Write-Host "  SHA256: $($hash.Hash)"
        } catch {
            Write-Host "  Exists: true (metadata read failed: $_)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Exists: false" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "[E] Recent Service Control Manager events (System log):" -ForegroundColor Cyan
    try {
        $sysEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction Stop |
            Where-Object { $_.Message -match $Name } |
            Select-Object -First 8 TimeCreated, Id, LevelDisplayName, Message
        if ($null -eq $sysEvents -or $sysEvents.Count -eq 0) {
            Write-Host "  No recent matching events in the last 30 minutes."
        } else {
            $sysEvents | ForEach-Object {
                Write-Host "  [$($_.TimeCreated)] Id=$($_.Id) Level=$($_.LevelDisplayName)"
                Write-Host "  $($_.Message -replace "`r`n", ' ')"
            }
        }
    } catch {
        Write-Host "  Could not query System events: $_" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "[F] Recent DocumentAgent events (Application log):" -ForegroundColor Cyan
    try {
        $appEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction Stop |
            Where-Object { $_.Message -match 'DocumentAgent|DocumentAgent.Worker' } |
            Select-Object -First 8 TimeCreated, ProviderName, Id, LevelDisplayName, Message
        if ($null -eq $appEvents -or $appEvents.Count -eq 0) {
            Write-Host "  No recent matching application events in the last 30 minutes."
        } else {
            $appEvents | ForEach-Object {
                Write-Host "  [$($_.TimeCreated)] Provider=$($_.ProviderName) Id=$($_.Id) Level=$($_.LevelDisplayName)"
                Write-Host "  $($_.Message -replace "`r`n", ' ')"
            }
        }
    } catch {
        Write-Host "  Could not query Application events: $_" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "[G] Latest agent log tail:" -ForegroundColor Cyan
    $logDir = Join-Path $AgentBasePath "logs"
    if (Test-Path $logDir) {
        $latestLog = Get-ChildItem -Path $logDir -File -Filter "*.log" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($null -ne $latestLog) {
            Write-Host "  Log file: $($latestLog.FullName)"
            Get-Content -Path $latestLog.FullName -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
        } else {
            Write-Host "  No .log files found in: $logDir"
        }
    } else {
        Write-Host "  Log directory not found: $logDir"
    }

    Write-Host "=============================================" -ForegroundColor Yellow
}

# -- Require Administrator ----------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Please run this script as Administrator (right-click PowerShell -> Run as Administrator)." -ForegroundColor Red
    exit 1
}

# -- Uninstall ----------------------------------------------------------------
if ($Uninstall) {
    Write-Host "Stopping service '$ServiceName'..."
    sc.exe stop $ServiceName 2>$null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName 2>$null
    Write-Host "Service '$ServiceName' removed."
    exit 0
}

# -- Locate the exe -----------------------------------------------------------
# Mode A: exe sits next to this script (end-user distribution)
$ExeNextToScript = Join-Path $PSScriptRoot "DocumentAgent.Worker.exe"

# Mode B: running from source -- publish first, exe lands in .\publish\
$CsprojPath   = Join-Path $PSScriptRoot "DocumentAgent.Worker.csproj"
$PublishDir   = Join-Path $PSScriptRoot "publish"
$ExePublished = Join-Path $PublishDir "DocumentAgent.Worker.exe"

if (Test-Path $CsprojPath) {
    # -- Developer mode: publish from source ---------------------------------
    Write-Host "[1/6] Install mode: developer (building from source)" -ForegroundColor Cyan
    Write-Host "       Publish-only: $PublishRequested"

    if (Test-Path $PublishDir) {
        Write-Host "       Cleaning previous publish output..."
        Remove-Item -Path $PublishDir -Recurse -Force
    }

    Write-Host "       Publishing self-contained Windows executable..."
    dotnet publish "$CsprojPath" `
        --configuration Release `
        --runtime win-x64 `
        --self-contained true `
        --output "$PublishDir" `
        /p:PublishSingleFile=true `
        /p:IncludeNativeLibrariesForSelfExtract=true

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: dotnet publish failed (exit $LASTEXITCODE). Fix build errors and try again." -ForegroundColor Red
        exit 1
    }

    $ExePath = $ExePublished

    if ($PublishRequested) {
        Write-Host ""
        Write-Host "Published to: $PublishDir"
        Write-Host "Copy DocumentAgent.Worker.exe and install-service.ps1 to each laptop, then run the script as Administrator."
        exit 0
    }

} elseif (Test-Path $ExeNextToScript) {
    # -- End-user mode: exe already here, install directly -------------------
    # This branch only runs when the project file is NOT present.
    # If .csproj exists we always publish and install from .\publish\ to avoid
    # stale/incorrect binaries in the project root.
    $ExePath = $ExeNextToScript
    Write-Host "[1/6] Install mode: end-user (exe next to script)" -ForegroundColor Cyan

} else {
    Write-Host "ERROR: Cannot find DocumentAgent.Worker.exe or .csproj next to this script." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: Exe not found at: $ExePath" -ForegroundColor Red
    exit 1
}

Write-Host "[2/6] Exe located: $ExePath" -ForegroundColor Cyan

# -- Remove existing service if present --------------------------------------
Write-Host "[3/6] Checking for existing service..." -ForegroundColor Cyan
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $existingService) {
    Write-Host "       Existing service found (Status=$($existingService.Status)) -- removing..."
    sc.exe stop $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 2
    Write-Host "       Old service removed."
} else {
    Write-Host "       No existing service -- clean install."
}

# -- Create service ----------------------------------------------------------
Write-Host "[4/6] Creating Windows Service..." -ForegroundColor Cyan

$binPathArg = "binPath= `"$ExePath`""
$displayArg = "DisplayName= `"$ServiceDisplay`""
$startArg   = "start= auto"

$createCmd = "sc.exe create $ServiceName $binPathArg $displayArg $startArg"
Write-Host "       Command: $createCmd"

# Use cmd /c to avoid PowerShell argument-mangling with sc.exe
cmd /c "sc.exe create $ServiceName binPath= `"$ExePath`" DisplayName= `"$ServiceDisplay`" start= auto"
$createExit = $LASTEXITCODE
Write-Host "       sc.exe create exit code: $createExit"

if ($createExit -ne 0) {
    Write-Host "FAILED: sc.exe create returned $createExit" -ForegroundColor Red
    Write-Host ""
    Write-Host "Try this manually:" -ForegroundColor Yellow
    Write-Host "  sc.exe create $ServiceName binPath= `"$ExePath`" start= auto"
    Write-Host ""
    Write-Host "If you see error 1072, wait 10 seconds (or reboot) and retry."
    exit 1
}

# Set description
cmd /c "sc.exe description $ServiceName `"$ServiceDesc`""
Write-Host "       Description set (exit $LASTEXITCODE)"

# Auto-restart on failure
cmd /c "sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000"
Write-Host "       Failure recovery set (exit $LASTEXITCODE)"

# -- Verify service was created ----------------------------------------------
# -- Stamp the real user's DocumentAgent path into the service environment ----
# Windows Services run as LocalSystem whose «MyDocuments» path is
# C:\Windows\system32\config\systemprofile\Documents — NOT the real user's folder.
# We store the correct path in the service's registry Environment block so the
# agent always reads/writes config, logs and scanned files from the right place.
Write-Host "[4b/6] Setting DOCUMENTAGENT_BASE_PATH in service environment..." -ForegroundColor Cyan
try {
    $realDocs      = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
    $agentBasePath = Join-Path $realDocs "DocumentAgent"
    $regPath       = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    Set-ItemProperty -Path $regPath -Name "Environment" -Value @("DOCUMENTAGENT_BASE_PATH=$agentBasePath") -Type MultiString
    Write-Host "       DOCUMENTAGENT_BASE_PATH = $agentBasePath" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not set service environment variable: $_" -ForegroundColor Yellow
    Write-Host "         The service may use the wrong data directory.  Set DOCUMENTAGENT_BASE_PATH manually."
}

Write-Host "[5/6] Verifying service exists..." -ForegroundColor Cyan
$created = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $created) {
    Write-Host "FAILED: Service '$ServiceName' not found after create!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Run these for diagnostics:" -ForegroundColor Yellow
    Write-Host "  sc.exe qc $ServiceName"
    Write-Host "  Get-WinEvent -LogName System -MaxEvents 30 | Where-Object { `$_.Message -match 'DocumentAgent' }"
    exit 1
}
Write-Host "       Service exists: Name=$($created.Name) Status=$($created.Status) StartType=$($created.StartType)"

# -- Start service -----------------------------------------------------------
Write-Host "[6/6] Starting service..." -ForegroundColor Cyan
cmd /c "sc.exe start $ServiceName"
$startExit = $LASTEXITCODE
Write-Host "       sc.exe start exit code: $startExit"
Start-Sleep -Seconds 3

$running = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$finalStatus = if ($null -ne $running) { $running.Status } else { "NOT FOUND" }
Write-Host "       Service status: $finalStatus"

if ($startExit -ne 0) {
    Write-Host "WARNING: Service created but failed to start (exit $startExit)." -ForegroundColor Yellow
    Write-Host "         Service binary configuration:" -ForegroundColor Yellow
    sc.exe qc $ServiceName | Select-String -Pattern "BINARY_PATH_NAME" | ForEach-Object { Write-Host "         $_" }
    Write-Host "         Check logs at: $env:USERPROFILE\Documents\DocumentAgent\logs"
    Write-Host "         Or Event Viewer > Windows Logs > Application"
}

# -- Summary -----------------------------------------------------------------
$ConfigPath = "$env:USERPROFILE\Documents\DocumentAgent\agent.config.json"
$LogPath    = "$env:USERPROFILE\Documents\DocumentAgent\logs"
$AgentBasePath = "$env:USERPROFILE\Documents\DocumentAgent"

Write-Host ""
if ($finalStatus -eq "Running") {
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host " DocumentAgent installed successfully" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
} else {
    Write-Host "==========================================" -ForegroundColor Yellow
    Write-Host " DocumentAgent installed with warnings" -ForegroundColor Yellow
    Write-Host "==========================================" -ForegroundColor Yellow
}
Write-Host " Exe:     $ExePath"
Write-Host " Config:  $ConfigPath"
Write-Host " Logs:    $LogPath"
Write-Host " Status:  $finalStatus"
Write-Host ""

if ($startExit -ne 0 -or $finalStatus -ne "Running") {
    Show-ServiceDiagnostics -Name $ServiceName -ExePath $ExePath -AgentBasePath $AgentBasePath
}

if (-not (Test-Path $ConfigPath)) {
    Write-Host "NEXT STEP: Create the config file at:" -ForegroundColor Yellow
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
    Write-Host "Then restart the service:  Restart-Service $ServiceName"
} else {
    Write-Host "Config file already exists -- service is ready."
}

Write-Host ""
Write-Host "To uninstall:  .\install-service.ps1 -Uninstall"
