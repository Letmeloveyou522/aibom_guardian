param(
    [ValidateSet('Install', 'Run', 'Status', 'Disable', 'Enable')]
    [string]$Action = 'Status',
    [string]$PythonPath,
    [ValidateRange(1, 24)]
    [int]$IntervalHours = 1
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $projectRoot '.aibom-guardian'
$configPath = Join-Path $stateDirectory 'windows-monitor.json'
$databasePath = Join-Path $stateDirectory 'monitor.db'
$secretPath = Join-Path $stateDirectory 'slack-webhook.dpapi'
$resultPath = Join-Path $stateDirectory 'last-run.json'
$env:PYTHONPATH = Join-Path $projectRoot 'src'

if ($Action -eq 'Install') {
    if (-not $PythonPath) { $PythonPath = (Get-Command python -ErrorAction Stop).Source }
    $PythonPath = (Resolve-Path -LiteralPath $PythonPath).Path
    if (-not (Test-Path -LiteralPath $secretPath)) {
        throw 'Configure .aibom-guardian/slack-webhook.dpapi before installation.'
    }
    if (-not (Test-Path -LiteralPath $databasePath)) {
        & $PythonPath -X utf8 -m aibom_guardian.monitoring init (Join-Path $projectRoot 'scan_report.json') --db $databasePath
        if ($LASTEXITCODE -ne 0) { throw 'Monitor baseline initialization failed.' }
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $suffix = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($projectRoot)))).Replace('-', '').Substring(0, 8)
    } finally { $sha.Dispose() }
    $taskName = "AIBOM-Guardian-$suffix"
    $taskArguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Action Run'
    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing -and ($existing.Actions.Arguments -ne $taskArguments)) {
        throw 'A different scheduled task already uses this name.'
    }
    $config = [ordered]@{
        task_name = $taskName
        python = $PythonPath
        interval_hours = $IntervalHours
        source_report = (Join-Path $projectRoot 'scan_report.json')
    }
    $config | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $taskAction = New-ScheduledTaskAction -Execute $powershellPath -Argument $taskArguments -WorkingDirectory $projectRoot
    $triggers = @(
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours($IntervalHours) -RepetitionInterval (New-TimeSpan -Hours $IntervalHours)),
        (New-ScheduledTaskTrigger -AtLogOn -User $user)
    )
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $triggers -Principal $principal -Settings $settings -Description 'Check the fixed AIBOM inventory and send configured Slack change alerts.' -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    [PSCustomObject]@{ task_name = $taskName; started = $true; interval_hours = $IntervalHours } | ConvertTo-Json
    exit 0
}

if (-not (Test-Path -LiteralPath $configPath)) { throw 'Monitor is not installed.' }
$config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($Action -eq 'Run') {
    try {
        # DPAPI binds the webhook to this Windows user on this computer.
        $secure = (Get-Content -LiteralPath $secretPath -Raw).Trim() | ConvertTo-SecureString
        $credential = New-Object System.Management.Automation.PSCredential('webhook', $secure)
        $env:AIBOM_GUARDIAN_SLACK_WEBHOOK_URL = $credential.GetNetworkCredential().Password
        $output = & $config.python -X utf8 -m aibom_guardian.monitoring check --db $databasePath 2> (Join-Path $stateDirectory 'monitor-error.log')
        $checkExitCode = $LASTEXITCODE
        if ($checkExitCode -notin @(0, 3)) { throw 'Monitor check failed.' }
        $result = ($output -join "`n") | ConvertFrom-Json
        $output | Set-Content -LiteralPath $resultPath -Encoding UTF8
        Remove-Item -LiteralPath (Join-Path $stateDirectory 'runner-error.json') -ErrorAction SilentlyContinue
        if (-not $result.complete -or $result.notification.pending_count -gt 0) { exit 1 }
        exit 0
    } catch {
        # Exception text may contain credentials; persist only the error class.
        [PSCustomObject]@{ at = (Get-Date).ToUniversalTime().ToString('o'); error = $_.Exception.GetType().Name } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stateDirectory 'runner-error.json') -Encoding UTF8
        exit 1
    } finally {
        Remove-Item Env:AIBOM_GUARDIAN_SLACK_WEBHOOK_URL -ErrorAction SilentlyContinue
    }
}
if ($Action -eq 'Disable') {
    Disable-ScheduledTask -TaskName $config.task_name | Out-Null
    Stop-ScheduledTask -TaskName $config.task_name
} elseif ($Action -eq 'Enable') {
    Enable-ScheduledTask -TaskName $config.task_name | Out-Null
    Start-ScheduledTask -TaskName $config.task_name
}
$task = Get-ScheduledTask -TaskName $config.task_name
$info = Get-ScheduledTaskInfo -TaskName $config.task_name
[PSCustomObject]@{
    task_name = $config.task_name
    state = [string]$task.State
    interval_hours = $config.interval_hours
    last_run = $info.LastRunTime.ToString('o')
    next_run = $info.NextRunTime.ToString('o')
    last_task_result = $info.LastTaskResult
    result_file = $resultPath
} | ConvertTo-Json
