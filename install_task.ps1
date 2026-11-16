$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path $PSScriptRoot).Path
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$taskName = "RansomwareLive Telecom CTI Monitor"
$timeZone = [System.TimeZoneInfo]::Local
if ($timeZone.Id -ne "India Standard Time") {
    throw "This installer schedules wall-clock times in the computer's local time zone. Set Windows time zone to India Standard Time (IST) and run this installer again. Current zone: $($timeZone.Id)"
}
if (-not (Test-Path $python)) {
    throw "Virtual environment not found at $python. Create it and install requirements first."
}

$action = New-ScheduledTaskAction `
    -Execute $python `
    -Argument "`"$projectRoot\main.py`" --run-once" `
    -WorkingDirectory $projectRoot
$triggerTimes = @("08:30", "14:30", "20:30", "02:30")
$triggers = foreach ($triggerTime in $triggerTimes) {
    $hour, $minute = $triggerTime.Split(":")
    $at = Get-Date -Hour ([int]$hour) -Minute ([int]$minute) -Second 0
    New-ScheduledTaskTrigger -Daily -At $at
}
$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $triggers `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null

Write-Output "Installed daily task for 08:30, 14:30, 20:30, and 02:30 IST: $taskName"
