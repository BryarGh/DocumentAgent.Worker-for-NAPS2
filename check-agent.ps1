param(
    [int]$ScanPollSeconds = 90,
    [switch]$SkipActiveScan,
    [switch]$DumpLogs
)

Write-Host "=== DocumentAgent deep diagnostics ===" -ForegroundColor Cyan

$results = New-Object System.Collections.Generic.List[object]
function Add-CheckResult {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Details
    )
    $results.Add([pscustomobject]@{ Name = $Name; Status = $Status; Details = $Details }) | Out-Null
    $color = switch ($Status) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "Gray" }
    }
    Write-Host ("[{0}] {1} - {2}" -f $Status, $Name, $Details) -ForegroundColor $color
}

function Get-LatestLogFile {
    param([string]$LogDirectory)
    if (-not (Test-Path $LogDirectory)) { return $null }
    return Get-ChildItem -Path $LogDirectory -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Invoke-AgentGet {
    param([string]$Path)
    return Invoke-RestMethod -Uri ("http://127.0.0.1:3333{0}" -f $Path) -Method GET -ErrorAction Stop
}

function Invoke-AgentPost {
    param(
        [string]$Path,
        [object]$Body
    )
    $json = $Body | ConvertTo-Json -Depth 8
    return Invoke-RestMethod -Uri ("http://127.0.0.1:3333{0}" -f $Path) -Method POST -ContentType "application/json" -Body $json -ErrorAction Stop
}

$docRoot = Join-Path $env:USERPROFILE "Documents\DocumentAgent"
$configPath = Join-Path $docRoot "agent.config.json"
$logDir = Join-Path $docRoot "logs"
$tmpDir = Join-Path $docRoot "tmp"
$serviceName = "DocumentAgent"
$jobId = $null
$naps2Path = $null
$profileToUse = $null

Write-Host "\n-- Environment --" -ForegroundColor Yellow
Write-Host "Machine: $env:COMPUTERNAME"
Write-Host "User: $env:USERNAME"
Write-Host "Timestamp: $(Get-Date -Format o)"
Write-Host "Doc root: $docRoot"

Write-Host "\n-- Service status & account --" -ForegroundColor Yellow
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Add-CheckResult -Name "ServiceInstalled" -Status "FAIL" -Details "Service '$serviceName' not found"
} else {
    $svcCim = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    $startName = if ($svcCim) { $svcCim.StartName } else { "(unknown)" }
    Add-CheckResult -Name "ServiceState" -Status (if ($svc.Status -eq 'Running') { "PASS" } else { "WARN" }) -Details "Status=$($svc.Status), StartType=$($svc.StartType), Account=$startName"
}

Write-Host "\n-- Config validation --" -ForegroundColor Yellow
if (-not (Test-Path $configPath)) {
    Add-CheckResult -Name "ConfigFile" -Status "FAIL" -Details "Missing: $configPath"
} else {
    Add-CheckResult -Name "ConfigFile" -Status "PASS" -Details "Found: $configPath"
    try {
        $raw = Get-Content $configPath -Raw -ErrorAction Stop
        $cfg = $raw | ConvertFrom-Json -ErrorAction Stop

        $naps2Path = [string]$cfg.naps2_path
        if ([string]::IsNullOrWhiteSpace($naps2Path)) {
            Add-CheckResult -Name "Config.naps2_path" -Status "FAIL" -Details "naps2_path is empty"
        } elseif (Test-Path $naps2Path) {
            Add-CheckResult -Name "Config.naps2_path" -Status "PASS" -Details "Exists: $naps2Path"
        } else {
            Add-CheckResult -Name "Config.naps2_path" -Status "FAIL" -Details "Path does not exist: $naps2Path"
        }

        $uploadUrl = [string]$cfg.upload_url
        Add-CheckResult -Name "Config.upload_url" -Status (if ([string]::IsNullOrWhiteSpace($uploadUrl)) { "WARN" } else { "PASS" }) -Details (if ([string]::IsNullOrWhiteSpace($uploadUrl)) { "upload_url not set" } else { $uploadUrl })

        $agentToken = [string]$cfg.agent_token
        Add-CheckResult -Name "Config.agent_token" -Status (if ([string]::IsNullOrWhiteSpace($agentToken)) { "WARN" } else { "PASS" }) -Details (if ([string]::IsNullOrWhiteSpace($agentToken)) { "agent_token not set" } else { "token present" })
    }
    catch {
        Add-CheckResult -Name "Config.Parse" -Status "FAIL" -Details $_.Exception.Message
    }
}

Write-Host "\n-- Local directory write test --" -ForegroundColor Yellow
try {
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $probe = Join-Path $tmpDir ("diag-write-{0}.txt" -f ([guid]::NewGuid().ToString("N")))
    "ok" | Out-File -FilePath $probe -Encoding utf8 -ErrorAction Stop
    Remove-Item $probe -Force -ErrorAction Stop
    Add-CheckResult -Name "DiskWrite" -Status "PASS" -Details "Can write/delete in $tmpDir"
}
catch {
    Add-CheckResult -Name "DiskWrite" -Status "FAIL" -Details $_.Exception.Message
}

Write-Host "\n-- NAPS2 checks --" -ForegroundColor Yellow
if ([string]::IsNullOrWhiteSpace($naps2Path) -or -not (Test-Path $naps2Path)) {
    Add-CheckResult -Name "NAPS2Executable" -Status "FAIL" -Details "naps2_path invalid or missing"
}
else {
    Add-CheckResult -Name "NAPS2Executable" -Status "PASS" -Details $naps2Path

    $drivers = @("twain", "wia", "escl")
    foreach ($driver in $drivers) {
        try {
            $output = & "$naps2Path" --listdevices --driver $driver 2>&1
            $exit = $LASTEXITCODE
            $joined = ($output | ForEach-Object { $_.ToString() }) -join " | "
            if ($exit -eq 0) {
                Add-CheckResult -Name ("NAPS2.listdevices.{0}" -f $driver) -Status "PASS" -Details (if ([string]::IsNullOrWhiteSpace($joined)) { "exit=0 (no output)" } else { "exit=0 $joined" })
            } else {
                Add-CheckResult -Name ("NAPS2.listdevices.{0}" -f $driver) -Status "WARN" -Details "exit=$exit $joined"
            }
        }
        catch {
            Add-CheckResult -Name ("NAPS2.listdevices.{0}" -f $driver) -Status "FAIL" -Details $_.Exception.Message
        }
    }

    try {
        $profilesOut = & "$naps2Path" --listprofiles 2>&1
        $profilesExit = $LASTEXITCODE
        $profiles = @($profilesOut | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ -ne "" })
        if ($profilesExit -eq 0 -and $profiles.Count -gt 0) {
            $profileToUse = $profiles[0]
            Add-CheckResult -Name "NAPS2.listprofiles" -Status "PASS" -Details ("Found {0} profile(s). First='{1}'" -f $profiles.Count, $profileToUse)
        }
        elseif ($profilesExit -eq 0) {
            Add-CheckResult -Name "NAPS2.listprofiles" -Status "WARN" -Details "exit=0 but no profiles found"
        }
        else {
            Add-CheckResult -Name "NAPS2.listprofiles" -Status "WARN" -Details ("exit={0} output={1}" -f $profilesExit, (($profilesOut | ForEach-Object { $_.ToString() }) -join " | "))
        }
    }
    catch {
        Add-CheckResult -Name "NAPS2.listprofiles" -Status "FAIL" -Details $_.Exception.Message
    }

    if (-not $SkipActiveScan -and -not [string]::IsNullOrWhiteSpace($profileToUse)) {
        try {
            $directOut = Join-Path $env:TEMP ("agent-direct-{0}.pdf" -f ([guid]::NewGuid().ToString("N")))
            $directRun = & "$naps2Path" --profile "$profileToUse" --output "$directOut" 2>&1
            $directExit = $LASTEXITCODE
            if ($directExit -eq 0 -and (Test-Path $directOut)) {
                $size = (Get-Item $directOut).Length
                Add-CheckResult -Name "NAPS2.direct_scan" -Status "PASS" -Details ("exit=0 output={0} bytes={1}" -f $directOut, $size)
                Remove-Item $directOut -Force -ErrorAction SilentlyContinue
            }
            else {
                Add-CheckResult -Name "NAPS2.direct_scan" -Status "WARN" -Details ("exit={0} output_exists={1} output={2}" -f $directExit, (Test-Path $directOut), (($directRun | ForEach-Object { $_.ToString() }) -join " | "))
            }
        }
        catch {
            Add-CheckResult -Name "NAPS2.direct_scan" -Status "FAIL" -Details $_.Exception.Message
        }
    }
}

Write-Host "\n-- Agent HTTP API checks --" -ForegroundColor Yellow
$health = $null
$status = $null
$scanners = $null
$profilesApi = $null

try {
    $health = Invoke-AgentGet -Path "/health"
    Add-CheckResult -Name "API.health" -Status "PASS" -Details ($health | ConvertTo-Json -Compress)
}
catch {
    Add-CheckResult -Name "API.health" -Status "FAIL" -Details $_.Exception.Message
}

try {
    $status = Invoke-AgentGet -Path "/status"
    Add-CheckResult -Name "API.status" -Status "PASS" -Details ($status | ConvertTo-Json -Compress)
}
catch {
    Add-CheckResult -Name "API.status" -Status "FAIL" -Details $_.Exception.Message
}

try {
    $scanners = Invoke-AgentGet -Path "/scanners"
    $scannerCount = @($scanners.profiles).Count
    Add-CheckResult -Name "API.scanners" -Status (if ($scannerCount -gt 0) { "PASS" } else { "WARN" }) -Details ("profiles={0}" -f $scannerCount)
}
catch {
    Add-CheckResult -Name "API.scanners" -Status "FAIL" -Details $_.Exception.Message
}

try {
    $profilesApi = Invoke-AgentGet -Path "/profiles"
    $profileCount = @($profilesApi.profiles).Count
    Add-CheckResult -Name "API.profiles" -Status "PASS" -Details ("profiles={0}" -f $profileCount)
}
catch {
    Add-CheckResult -Name "API.profiles" -Status "FAIL" -Details $_.Exception.Message
}

Write-Host "\n-- End-to-end API scan test --" -ForegroundColor Yellow
if (-not $SkipActiveScan -and $scanners -and @($scanners.profiles).Count -gt 0) {
    try {
        $scannerName = [string]$scanners.profiles[0].name
        $diagProfile = "diag-" + (Get-Date -Format "yyyyMMdd-HHmmss")

        $profileBody = @{
            profile_name = $diagProfile
            scanner_name = $scannerName
            dpi = 300
            color_mode = "color"
            source = "ADF"
            duplex = $false
            paper_size = "A4"
        }

        $profileRes = Invoke-AgentPost -Path "/profiles" -Body $profileBody
        Add-CheckResult -Name "API.create_profile" -Status "PASS" -Details ("saved={0} profile={1} scanner={2}" -f $profileRes.saved, $diagProfile, $scannerName)

        $scanBody = @{
            document_id = "DIAG-" + ([guid]::NewGuid().ToString("N").Substring(0, 12))
            profile_name = $diagProfile
            client_request_id = "DIAG-" + ([guid]::NewGuid().ToString("N").Substring(0, 12))
        }

        $scanRes = Invoke-AgentPost -Path "/scan" -Body $scanBody
        $jobId = [string]$scanRes.job_id
        Add-CheckResult -Name "API.start_scan" -Status "PASS" -Details ("job_id={0} status={1}" -f $jobId, $scanRes.status)

        $deadline = (Get-Date).AddSeconds($ScanPollSeconds)
        $lastStatus = "queued"
        do {
            Start-Sleep -Seconds 2
            $job = Invoke-AgentGet -Path ("/scan/{0}" -f $jobId)
            $lastStatus = [string]$job.status
            Write-Host ("Polling job {0}: status={1} error={2}" -f $jobId, $job.status, $job.error_message) -ForegroundColor Gray
            if ($lastStatus -eq "completed") {
                Add-CheckResult -Name "API.scan_completion" -Status "PASS" -Details "completed"
                break
            }
            if ($lastStatus -eq "failed") {
                Add-CheckResult -Name "API.scan_completion" -Status "FAIL" -Details ("failed error_message={0}" -f $job.error_message)
                break
            }
        } while ((Get-Date) -lt $deadline)

        if ($lastStatus -ne "completed" -and $lastStatus -ne "failed") {
            Add-CheckResult -Name "API.scan_completion" -Status "WARN" -Details ("timeout waiting for final status (last={0})" -f $lastStatus)
        }
    }
    catch {
        Add-CheckResult -Name "API.e2e_scan" -Status "FAIL" -Details $_.Exception.Message
    }
}
elseif ($SkipActiveScan) {
    Add-CheckResult -Name "API.e2e_scan" -Status "WARN" -Details "Skipped by -SkipActiveScan"
}
else {
    Add-CheckResult -Name "API.e2e_scan" -Status "WARN" -Details "No scanners available from /scanners"
}

Write-Host "\n-- Logs --" -ForegroundColor Yellow
$latest = Get-LatestLogFile -LogDirectory $logDir
if ($null -eq $latest) {
    Add-CheckResult -Name "Logs.latest" -Status "WARN" -Details "No log file found in $logDir"
}
else {
    Add-CheckResult -Name "Logs.latest" -Status "PASS" -Details $latest.FullName

    if ($DumpLogs) {
        Write-Host "--- Last 300 lines ---" -ForegroundColor DarkCyan
        Get-Content -Path $latest.FullName -Tail 300 -ErrorAction SilentlyContinue
    }

    if (-not [string]::IsNullOrWhiteSpace($jobId)) {
        Write-Host ("--- Log lines for job {0} ---" -f $jobId) -ForegroundColor DarkCyan
        Select-String -Path $latest.FullName -Pattern $jobId -SimpleMatch -ErrorAction SilentlyContinue | ForEach-Object { $_.Line }
    }
}

Write-Host "\n-- Service-session hint --" -ForegroundColor Yellow
Write-Host "If direct NAPS2 scan passes but API e2e scan fails, run the worker interactively under your user to confirm service-session access differences."
Write-Host "1) Stop service: Stop-Service DocumentAgent -Force"
Write-Host "2) Start worker manually: & 'C:\path\to\DocumentAgent.Worker.exe'"
Write-Host "3) Re-run this script with -SkipActiveScan:$false"
Write-Host "4) Compare results with service mode"

Write-Host "\n=== Summary ===" -ForegroundColor Cyan
$pass = @($results | Where-Object Status -eq "PASS").Count
$warn = @($results | Where-Object Status -eq "WARN").Count
$fail = @($results | Where-Object Status -eq "FAIL").Count
Write-Host ("PASS={0} WARN={1} FAIL={2}" -f $pass, $warn, $fail) -ForegroundColor Cyan

$results | Sort-Object Name | Format-Table -AutoSize

Write-Host "\nDone. Paste this output if you want a precise root-cause analysis." -ForegroundColor Cyan
