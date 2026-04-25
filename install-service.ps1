# DocumentAgent Windows Installer -- Service or Startup Task
#
# -- FOR END USERS (no source code / no SDK needed) --------------------------
#   1. Copy DocumentAgent.Worker.exe and this script into the same folder
#      (e.g. D:\DocumentAgent\)
#   2. Right-click PowerShell -> Run as Administrator
#   3. cd to that folder, then run one of:
#      .\install-service.ps1
#      .\install-service.ps1 -StartupTask
#
# -- FOR DEVELOPERS (building from source) -----------------------------------
#   Run from the project root (where .csproj lives):
#   .\install-service.ps1                 -- publishes then installs as service
#   .\install-service.ps1 -StartupTask    -- publishes then installs as startup task
#   .\install-service.ps1 -Publish        -- only publishes to .\publish\
#
# -- UNINSTALL ----------------------------------------------------------------
#   .\install-service.ps1 -Uninstall
#   .\install-service.ps1 -StartupTask -Uninstall

param(
    [switch]$Uninstall,
    [switch]$Publish,
    [switch]$StartupTask
)

$ErrorActionPreference = 'Continue'

$PublishRequested = $PSBoundParameters.ContainsKey('Publish') -and $Publish.IsPresent
$InstallMode = if ($StartupTask) { 'startup-task' } else { 'service' }

$ServiceName = 'DocumentAgent'
$ServiceDisplay = 'Document Agent (NAPS2 Scanner)'
$ServiceDesc = 'Loopback scanning agent that drives NAPS2 and uploads scanned PDFs to your Laravel server.'
$TaskName = 'DocumentAgent-Startup'
$TaskDesc = 'Starts DocumentAgent.Worker at user logon for interactive scanner access.'

function Show-LogTail {
    param(
        [string]$AgentBasePath
    )

    Write-Host ''
    Write-Host '[Logs] Latest agent log tail:' -ForegroundColor Cyan
    $logDir = Join-Path $AgentBasePath 'logs'
    if (Test-Path $logDir) {
        $latestLog = Get-ChildItem -Path $logDir -File -Filter '*.log' -ErrorAction SilentlyContinue |
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
}

function Show-ServiceDiagnostics {
    param(
        [string]$Name,
        [string]$ExePath,
        [string]$AgentBasePath
    )

    Write-Host ''
    Write-Host '========= DocumentAgent Service Diagnostics =========' -ForegroundColor Yellow

    Write-Host '[A] Service config (sc qc):' -ForegroundColor Cyan
    cmd /c "sc.exe qc $Name"

    Write-Host ''
    Write-Host '[B] Service runtime state (sc queryex):' -ForegroundColor Cyan
    cmd /c "sc.exe queryex $Name"

    Write-Host ''
    Write-Host '[C] Service registry Environment block:' -ForegroundColor Cyan
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        $envBlock = (Get-ItemProperty -Path $regPath -Name 'Environment' -ErrorAction Stop).Environment
        if ($null -eq $envBlock -or $envBlock.Count -eq 0) {
            Write-Host '(empty)'
        } else {
            $envBlock | ForEach-Object { Write-Host "  $_" }
        }
    } catch {
        Write-Host "Unable to read Environment registry value: $_" -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host '[D] Exe path + file metadata:' -ForegroundColor Cyan
    Write-Host "  ExePath: $ExePath"
    if (Test-Path $ExePath) {
        try {
            $item = Get-Item $ExePath
            $hash = Get-FileHash -Path $ExePath -Algorithm SHA256
            Write-Host '  Exists: true'
            Write-Host "  Size: $($item.Length) bytes"
            Write-Host "  LastWrite: $($item.LastWriteTime)"
            Write-Host "  SHA256: $($hash.Hash)"
        } catch {
            Write-Host "  Exists: true (metadata read failed: $_)" -ForegroundColor Yellow
        }
    } else {
        Write-Host '  Exists: false' -ForegroundColor Red
    }

    Write-Host ''
    Write-Host '[E] Recent Service Control Manager events (System log):' -ForegroundColor Cyan
    try {
        $sysEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction Stop |
            Where-Object { $_.Message -match $Name } |
            Select-Object -First 8 TimeCreated, Id, LevelDisplayName, Message
        if ($null -eq $sysEvents -or $sysEvents.Count -eq 0) {
            Write-Host '  No recent matching events in the last 30 minutes.'
        } else {
            $sysEvents | ForEach-Object {
                Write-Host "  [$($_.TimeCreated)] Id=$($_.Id) Level=$($_.LevelDisplayName)"
                Write-Host "  $($_.Message -replace \"`r`n\", ' ')"
            }
        }
    } catch {
        Write-Host "  Could not query System events: $_" -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host '[F] Recent DocumentAgent events (Application log):' -ForegroundColor Cyan
    try {
        $appEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction Stop |
            Where-Object { $_.Message -match 'DocumentAgent|DocumentAgent.Worker' } |
            Select-Object -First 8 TimeCreated, ProviderName, Id, LevelDisplayName, Message
        if ($null -eq $appEvents -or $appEvents.Count -eq 0) {
            Write-Host '  No recent matching application events in the last 30 minutes.'
        } else {
            $appEvents | ForEach-Object {
                Write-Host "  [$($_.TimeCreated)] Provider=$($_.ProviderName) Id=$($_.Id) Level=$($_.LevelDisplayName)"
                Write-Host "  $($_.Message -replace \"`r`n\", ' ')"
            }
        }
    } catch {
        Write-Host "  Could not query Application events: $_" -ForegroundColor Yellow
    }

    Show-LogTail -AgentBasePath $AgentBasePath
    Write-Host '====================================================' -ForegroundColor Yellow
}

function Show-StartupTaskDiagnostics {
    param(
        [string]$Name,
        [string]$ExePath,
        [string]$AgentBasePath
    )

    Write-Host ''
    Write-Host '======= DocumentAgent Startup Task Diagnostics =======' -ForegroundColor Yellow

    Write-Host '[A] Scheduled task summary:' -ForegroundColor Cyan
    try {
        $task = Get-ScheduledTask -TaskName $Name -ErrorAction Stop
        $task | Select-Object TaskName, State, Author, Description | Format-List
    } catch {
        Write-Host "  Could not query scheduled task: $_" -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host '[B] Scheduled task runtime info:' -ForegroundColor Cyan
    try {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $Name -ErrorAction Stop
        $taskInfo | Select-Object LastRunTime, LastTaskResult, NextRunTime, NumberOfMissedRuns | Format-List
    } catch {
        Write-Host "  Could not query scheduled task info: $_" -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host '[C] Exe path + file metadata:' -ForegroundColor Cyan
    Write-Host "  ExePath: $ExePath"
    if (Test-Path $ExePath) {
        try {
            $item = Get-Item $ExePath
            $hash = Get-FileHash -Path $ExePath -Algorithm SHA256
            Write-Host '  Exists: true'
            Write-Host "  Size: $($item.Length) bytes"
            Write-Host "  LastWrite: $($item.LastWriteTime)"
            Write-Host "  SHA256: $($hash.Hash)"
        } catch {
            Write-Host "  Exists: true (metadata read failed: $_)" -ForegroundColor Yellow
        }
    } else {
        Write-Host '  Exists: false' -ForegroundColor Red
    }

    Write-Host ''
    Write-Host '[D] Recent Task Scheduler events:' -ForegroundColor Cyan
    try {
        $taskEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction Stop |
            Where-Object { $_.Message -match $Name } |
            Select-Object -First 8 TimeCreated, Id, LevelDisplayName, Message
        if ($null -eq $taskEvents -or $taskEvents.Count -eq 0) {
            Write-Host '  No recent matching task events in the last 30 minutes.'
        } else {
            $taskEvents | ForEach-Object {
                Write-Host "  [$($_.TimeCreated)] Id=$($_.Id) Level=$($_.LevelDisplayName)"
                Write-Host "  $($_.Message -replace \"`r`n\", ' ')"
            }
        }
    } catch {
        Write-Host "  Could not query Task Scheduler events: $_" -ForegroundColor Yellow
    }

    Show-LogTail -AgentBasePath $AgentBasePath
    Write-Host '=====================================================' -ForegroundColor Yellow
}

function Remove-ServiceInstall {
    param(
        [string]$Name
    )

    $existingService = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $existingService) {
        Write-Host "Stopping service '$Name'..."
        sc.exe stop $Name 2>$null | Out-Null
        Start-Sleep -Seconds 2
        sc.exe delete $Name 2>$null | Out-Null
        Start-Sleep -Seconds 2
        Write-Host "Service '$Name' removed."
    } else {
        Write-Host "Service '$Name' not found."
    }
}

function Remove-StartupTaskInstall {
    param(
        [string]$Name
    )

    try {
        if (Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue) {
            Disable-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue | Out-Null
            Unregister-ScheduledTask -TaskName $Name -Confirm:$false
            Write-Host "Startup task '$Name' removed."
        } else {
            Write-Host "Startup task '$Name' not found."
        }
    } catch {
        Write-Host "WARNING: failed to remove startup task '$Name': $_" -ForegroundColor Yellow
    }
}

function Install-StartupTaskMode {
    param(
        [string]$Name,
        [string]$Description,
        [string]$ExePath
    )

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    Remove-ServiceInstall -Name $ServiceName
    Remove-StartupTaskInstall -Name $Name

    Write-Host '[3/6] Creating startup task...' -ForegroundColor Cyan
    $action = New-ScheduledTaskAction -Execute $ExePath
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew `
        -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest

    Register-ScheduledTask `
        -TaskName $Name `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description $Description | Out-Null

    Write-Host "       Startup task installed for user: $currentUser" -ForegroundColor Green

    Write-Host '[4/6] Starting startup task now...' -ForegroundColor Cyan
    Start-ScheduledTask -TaskName $Name
    Start-Sleep -Seconds 2

    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    $taskInfo = Get-ScheduledTaskInfo -TaskName $Name -ErrorAction SilentlyContinue

    return [pscustomobject]@{
        Mode = 'startup-task'
        State = if ($null -ne $task) { $task.State.ToString() } else { 'NotFound' }
        LastTaskResult = if ($null -ne $taskInfo) { $taskInfo.LastTaskResult } else { $null }
        StartExit = 0
    }
}

function Install-ServiceMode {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string]$Description,
        [string]$ExePath,
        [string]$AgentBasePath
    )

    Write-Host '[3/6] Checking for existing service...' -ForegroundColor Cyan
    Remove-StartupTaskInstall -Name $TaskName

    $existingService = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $existingService) {
        Write-Host "       Existing service found (Status=$($existingService.Status)) -- removing..."
        sc.exe stop $Name 2>$null | Out-Null
        Start-Sleep -Seconds 2
        sc.exe delete $Name 2>$null | Out-Null
        Start-Sleep -Seconds 2
        Write-Host '       Old service removed.'
    } else {
        Write-Host '       No existing service -- clean install.'
    }

    Write-Host '[4/6] Creating Windows Service...' -ForegroundColor Cyan

    $binPathArg = "binPath= `"$ExePath`""
    $displayArg = "DisplayName= `"$DisplayName`""
    $startArg = 'start= auto'
    $createCmd = "sc.exe create $Name $binPathArg $displayArg $startArg"
    Write-Host "       Command: $createCmd"

    cmd /c "sc.exe create $Name binPath= `"$ExePath`" DisplayName= `"$DisplayName`" start= auto"
    $createExit = $LASTEXITCODE
    Write-Host "       sc.exe create exit code: $createExit"

    if ($createExit -ne 0) {
        Write-Host "FAILED: sc.exe create returned $createExit" -ForegroundColor Red
        Write-Host ''
        Write-Host 'Try this manually:' -ForegroundColor Yellow
        Write-Host "  sc.exe create $Name binPath= `"$ExePath`" start= auto"
        Write-Host ''
        Write-Host 'If you see error 1072, wait 10 seconds (or reboot) and retry.'
        exit 1
    }

    cmd /c "sc.exe description $Name `"$Description`""
    Write-Host "       Description set (exit $LASTEXITCODE)"

    cmd /c "sc.exe failure $Name reset= 86400 actions= restart/60000/restart/60000/restart/60000"
    Write-Host "       Failure recovery set (exit $LASTEXITCODE)"

    Write-Host '[4b/6] Setting DOCUMENTAGENT_BASE_PATH in service environment...' -ForegroundColor Cyan
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        Set-ItemProperty -Path $regPath -Name 'Environment' -Value @("DOCUMENTAGENT_BASE_PATH=$AgentBasePath") -Type MultiString
        Write-Host "       DOCUMENTAGENT_BASE_PATH = $AgentBasePath" -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Could not set service environment variable: $_" -ForegroundColor Yellow
        Write-Host '         The service may use the wrong data directory. Set DOCUMENTAGENT_BASE_PATH manually.'
    }

    Write-Host '[5/6] Verifying service exists...' -ForegroundColor Cyan
    $created = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $created) {
        Write-Host "FAILED: Service '$Name' not found after create!" -ForegroundColor Red
        Write-Host ''
        Write-Host 'Run these for diagnostics:' -ForegroundColor Yellow
        Write-Host "  sc.exe qc $Name"
        Write-Host "  Get-WinEvent -LogName System -MaxEvents 30 | Where-Object { `$_.Message -match 'DocumentAgent' }"
        exit 1
    }
    Write-Host "       Service exists: Name=$($created.Name) Status=$($created.Status) StartType=$($created.StartType)"

    Write-Host '[6/6] Starting service...' -ForegroundColor Cyan
    cmd /c "sc.exe start $Name"
    $startExit = $LASTEXITCODE
    Write-Host "       sc.exe start exit code: $startExit"
    Start-Sleep -Seconds 3

    $running = Get-Service -Name $Name -ErrorAction SilentlyContinue
    $finalStatus = if ($null -ne $running) { $running.Status.ToString() } else { 'NOT FOUND' }
    Write-Host "       Service status: $finalStatus"

    if ($startExit -ne 0) {
        Write-Host "WARNING: Service created but failed to start (exit $startExit)." -ForegroundColor Yellow
        Write-Host '         Service binary configuration:' -ForegroundColor Yellow
        sc.exe qc $Name | Select-String -Pattern 'BINARY_PATH_NAME' | ForEach-Object { Write-Host "         $_" }
        Write-Host "         Check logs at: $AgentBasePath\logs"
        Write-Host '         Or Event Viewer > Windows Logs > Application'
    }

    return [pscustomobject]@{
        Mode = 'service'
        State = $finalStatus
        LastTaskResult = $null
        StartExit = $startExit
    }
}

function Show-ModeSummary {
    param(
        [string]$Mode,
        [string]$ExePath,
        [string]$ConfigPath,
        [string]$LogPath,
        [object]$InstallResult,
        [string]$AgentBasePath
    )

    Write-Host ''
    $healthy = if ($Mode -eq 'service') {
        $InstallResult.StartExit -eq 0 -and $InstallResult.State -eq 'Running'
    } else {
        $InstallResult.State -in @('Ready', 'Running', 'Queued')
    }

    if ($healthy) {
        Write-Host '==========================================' -ForegroundColor Green
        Write-Host ' DocumentAgent installed successfully' -ForegroundColor Green
        Write-Host '==========================================' -ForegroundColor Green
    } else {
        Write-Host '==========================================' -ForegroundColor Yellow
        Write-Host ' DocumentAgent installed with warnings' -ForegroundColor Yellow
        Write-Host '==========================================' -ForegroundColor Yellow
    }

    Write-Host " Mode:    $Mode"
    Write-Host " Exe:     $ExePath"
    Write-Host " Config:  $ConfigPath"
    Write-Host " Logs:    $LogPath"
    if ($Mode -eq 'service') {
        Write-Host " Status:  $($InstallResult.State)"
        Write-Host ' Start:   Runs at Windows boot via Service Control Manager'
        Write-Host ' Stop:    Stop-Service DocumentAgent'
        Write-Host ' Disable: Set-Service DocumentAgent -StartupType Disabled'
        Write-Host ' Enable:  Set-Service DocumentAgent -StartupType Automatic'
        Write-Host ' Remove:  .\install-service.ps1 -Uninstall'
    } else {
        Write-Host " Status:  $($InstallResult.State)"
        Write-Host ' Start:   Runs at user logon and was started immediately by installer'
        Write-Host ' Stop:    Stop-Process -Name DocumentAgent.Worker -ErrorAction SilentlyContinue'
        Write-Host " Disable: Disable-ScheduledTask -TaskName $TaskName"
        Write-Host " Enable:  Enable-ScheduledTask -TaskName $TaskName"
        Write-Host ' Remove:  .\install-service.ps1 -StartupTask -Uninstall'
    }

    Write-Host ''
    Write-Host 'Quick checks:' -ForegroundColor Cyan
    Write-Host '  curl http://127.0.0.1:3333/health'
    Write-Host '  curl http://127.0.0.1:3333/scanners'
    if ($Mode -eq 'service') {
        Write-Host '  Get-Service DocumentAgent'
    } else {
        Write-Host "  Get-ScheduledTask -TaskName $TaskName"
        Write-Host "  Get-ScheduledTaskInfo -TaskName $TaskName"
    }

    if (-not (Test-Path $ConfigPath)) {
        Write-Host ''
        Write-Host 'NEXT STEP: Create the config file at:' -ForegroundColor Yellow
        Write-Host "  $ConfigPath"
        Write-Host ''
        Write-Host 'Example content:'
        Write-Host '{
  "naps2_path": "C:\\Program Files\\NAPS2\\NAPS2.Console.exe",
  "upload_url": "http://192.168.33.50/api/document-agent/upload",
  "agent_token": "YOUR_TOKEN",
  "laravel_origin": "http://192.168.33.50"
}'
        Write-Host ''
        if ($Mode -eq 'service') {
            Write-Host "Then restart the service: Restart-Service $ServiceName"
        } else {
            Write-Host "Then restart the startup task: Start-ScheduledTask -TaskName $TaskName"
        }
    } else {
        Write-Host 'Config file already exists -- install is ready.'
    }

    if (-not $healthy) {
        if ($Mode -eq 'service') {
            Show-ServiceDiagnostics -Name $ServiceName -ExePath $ExePath -AgentBasePath $AgentBasePath
        } else {
            Show-StartupTaskDiagnostics -Name $TaskName -ExePath $ExePath -AgentBasePath $AgentBasePath
        }
    }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: Please run this script as Administrator (right-click PowerShell -> Run as Administrator).' -ForegroundColor Red
    exit 1
}

$realDocs = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
$AgentBasePath = Join-Path $realDocs 'DocumentAgent'
$ConfigPath = Join-Path $AgentBasePath 'agent.config.json'
$LogPath = Join-Path $AgentBasePath 'logs'

if ($Uninstall) {
    if ($InstallMode -eq 'startup-task') {
        Remove-StartupTaskInstall -Name $TaskName
    } else {
        Remove-ServiceInstall -Name $ServiceName
    }
    exit 0
}

$ExeNextToScript = Join-Path $PSScriptRoot 'DocumentAgent.Worker.exe'
$CsprojPath = Join-Path $PSScriptRoot 'DocumentAgent.Worker.csproj'
$PublishDir = Join-Path $PSScriptRoot 'publish'
$ExePublished = Join-Path $PublishDir 'DocumentAgent.Worker.exe'

if (Test-Path $CsprojPath) {
    Write-Host '[1/6] Install mode: developer (building from source)' -ForegroundColor Cyan
    Write-Host "       Publish-only: $PublishRequested"
    Write-Host "       Target runtime mode: $InstallMode"

    if (Test-Path $PublishDir) {
        Write-Host '       Cleaning previous publish output...'
        Remove-Item -Path $PublishDir -Recurse -Force
    }

    Write-Host '       Publishing self-contained Windows executable...'
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
        Write-Host ''
        Write-Host "Published to: $PublishDir"
        Write-Host 'Copy DocumentAgent.Worker.exe and install-service.ps1 to each laptop, then run the script as Administrator.'
        Write-Host 'Use -StartupTask on laptops where scanner acquisition only works in an interactive user session.'
        exit 0
    }
} elseif (Test-Path $ExeNextToScript) {
    $ExePath = $ExeNextToScript
    Write-Host '[1/6] Install mode: end-user (exe next to script)' -ForegroundColor Cyan
    Write-Host "       Target runtime mode: $InstallMode"
} else {
    Write-Host 'ERROR: Cannot find DocumentAgent.Worker.exe or .csproj next to this script.' -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: Exe not found at: $ExePath" -ForegroundColor Red
    exit 1
}

Write-Host "[2/6] Exe located: $ExePath" -ForegroundColor Cyan

$InstallResult = if ($InstallMode -eq 'startup-task') {
    Install-StartupTaskMode -Name $TaskName -Description $TaskDesc -ExePath $ExePath
} else {
    Install-ServiceMode -Name $ServiceName -DisplayName $ServiceDisplay -Description $ServiceDesc -ExePath $ExePath -AgentBasePath $AgentBasePath
}

Show-ModeSummary -Mode $InstallMode -ExePath $ExePath -ConfigPath $ConfigPath -LogPath $LogPath -InstallResult $InstallResult -AgentBasePath $AgentBasePath
