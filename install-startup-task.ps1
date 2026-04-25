# DocumentAgent Windows Startup Task -- Install / Uninstall
#
# Use this mode when scanner acquisition fails under Windows Service mode.
# It runs the agent in the logged-in user session (interactive desktop),
# which is generally required by TWAIN/WIA drivers.
#
# Install:
#   .\install-startup-task.ps1
#
# Uninstall:
#   .\install-startup-task.ps1 -Uninstall

param(
    [switch]$Uninstall,
    [string]$TaskName = "DocumentAgent-Startup"
)

$ErrorActionPreference = "Stop"

$exePath = Join-Path $PSScriptRoot "DocumentAgent.Worker.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "ERROR: DocumentAgent.Worker.exe was not found next to this script:" -ForegroundColor Red
    Write-Host "       $exePath" -ForegroundColor Red
    exit 1
}

if ($Uninstall) {
    try {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Host "Removed scheduled task: $TaskName" -ForegroundColor Green
        } else {
            Write-Host "Scheduled task not found: $TaskName"
        }
    } catch {
        Write-Host "ERROR removing scheduled task: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    exit 0
}

try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # Replace any existing task with same name
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    $action = New-ScheduledTaskAction -Execute $exePath
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew `
        -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "Starts DocumentAgent.Worker at user logon for interactive scanner access." | Out-Null

    # Start now so no logout/login is required
    Start-ScheduledTask -TaskName $TaskName

    Write-Host "Scheduled task installed: $TaskName" -ForegroundColor Green
    Write-Host "User: $currentUser"
    Write-Host "Executable: $exePath"
    Write-Host ""
    Write-Host "Quick checks:"
    Write-Host "  Get-ScheduledTask -TaskName $TaskName"
    Write-Host "  curl http://127.0.0.1:3333/health"
} catch {
    Write-Host "ERROR creating scheduled task: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
