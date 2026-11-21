<#
.SYNOPSIS
    Install the Antiquarian's Cage endpoint agent + privileged broker so they start automatically in the
    background on every boot/logon. Run from an ELEVATED PowerShell on an already-enrolled endpoint.

.DESCRIPTION
    Topology (why it is split this way):
      * The privileged BROKER runs as a LocalSystem Windows service (CageBroker, auto-start). It applies the
        signed, allowlisted privileged actions (RDP enable, restart, shutdown, logoff, account changes).
      * The AGENT runs as an ELEVATED, HIDDEN logon Scheduled Task in the interactive user session - NOT as a
        session-0 service. This is required: the mandatory RDP/Remote-Assistance on-screen banner can only be
        shown from an interactive session (see agent/cage_agent/remote/assist.py). Running elevated also means the
        agent's token carries Administrators, which the broker pipe admits - so RDP/assist/restart all work.

    Prerequisite: the endpoint must already be ENROLLED (config.json present), e.g.
        cage-agent.exe enroll --server https://<your-console> --token XXXXX-XXXXX-XXXXX-XXXXX-XXXXX

.PARAMETER SourceDir
    Folder containing cage-agent.exe, cage-broker.exe and cage-broker-service.exe. Default: this script's folder.

.PARAMETER InstallDir
    Where the exes are installed. Default: "$env:ProgramFiles\AntiquariansCage".

.PARAMETER DataDir
    The agent data directory (holds config.json). Default: "$env:ProgramData\AntiquariansCage".

.EXAMPLE
    # From an elevated PowerShell, in the folder holding the three exes:
    .\install.ps1
#>
[CmdletBinding()]
param(
    [string]$SourceDir  = $PSScriptRoot,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AntiquariansCage'),
    [string]$DataDir    = (Join-Path $env:ProgramData 'AntiquariansCage')
)

$ErrorActionPreference = 'Stop'
$TaskName = 'AntiquariansCageAgent'
$SvcName  = 'CageBroker'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an ELEVATED PowerShell (Run as administrator).'
    }
}

function Resolve-Exe([string]$name) {
    # Prefer SourceDir; fall back to the current directory.
    foreach ($d in @($SourceDir, (Get-Location).Path)) {
        $p = Join-Path $d $name
        if (Test-Path -LiteralPath $p) { return (Resolve-Path -LiteralPath $p).Path }
    }
    throw "Could not find $name in '$SourceDir' or the current folder. Put the three exes together and retry."
}

Assert-Admin

Write-Host '== Antiquarian''s Cage: installing auto-start (broker service + agent logon task) ==' -ForegroundColor Cyan

# 0) Locate the three executables up front so we fail fast if one is missing.
$agentSrc         = Resolve-Exe 'cage-agent.exe'
$brokerSrc        = Resolve-Exe 'cage-broker.exe'
$brokerServiceSrc = Resolve-Exe 'cage-broker-service.exe'

# 1) Require prior enrollment (config.json with a pinned command key).
$config = Join-Path $DataDir 'config.json'
if (-not (Test-Path -LiteralPath $config)) {
    throw "Not enrolled: '$config' not found. Enroll first:`n" +
          "  `"$agentSrc`" enroll --server https://<your-console> --token XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
}

# 2) Copy the exes into a stable install location.
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -LiteralPath $agentSrc,$brokerSrc,$brokerServiceSrc -Destination $InstallDir -Force
$agent         = Join-Path $InstallDir 'cage-agent.exe'
$broker        = Join-Path $InstallDir 'cage-broker.exe'
$brokerService = Join-Path $InstallDir 'cage-broker-service.exe'
Write-Host "  Installed exes -> $InstallDir" -ForegroundColor Green

# 3) Install (or reinstall) the broker as a LocalSystem auto-start service.
if (Get-Service -Name $SvcName -ErrorAction SilentlyContinue) {
    Write-Host "  Broker service already present; stopping to update." -ForegroundColor Yellow
    Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
    & $brokerService remove | Out-Null
    Start-Sleep -Seconds 1
}
& $brokerService --startup auto install
if ($LASTEXITCODE -ne 0) { throw "Broker service install failed (exit $LASTEXITCODE)." }

# 4) Pin the broker to THIS device's command-signing key (read from the enrolled agent config).
& $broker pin --agent-config $config
if ($LASTEXITCODE -ne 0) { throw "Broker pin failed (exit $LASTEXITCODE). Is the endpoint enrolled?" }

# 5) Lock down the broker state directory to SYSTEM + Administrators only.
$brokerState = Join-Path $DataDir 'broker'
New-Item -ItemType Directory -Force -Path $brokerState | Out-Null
& icacls.exe $brokerState /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

# 6) Start the broker service now.
Start-Service -Name $SvcName
Write-Host "  Broker service '$SvcName' installed, pinned and started." -ForegroundColor Green

# 7) Hidden launcher for the agent (a console exe would otherwise flash a window at logon).
$vbs = Join-Path $InstallDir 'run-agent-hidden.vbs'
@"
' Launches the Cage agent with no visible console window (0 = hidden).
CreateObject("WScript.Shell").Run """$agent"" run", 0, False
"@ | Set-Content -LiteralPath $vbs -Encoding ASCII

# 8) Register the agent as an elevated, hidden logon Scheduled Task (interactive session -> banner works).
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
$action    = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "`"$vbs`""
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -Hidden `
                -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description 'Antiquarian''s Cage endpoint agent (auto-start at logon).' | Out-Null
Write-Host "  Agent registered as logon task '$TaskName' (elevated, hidden)." -ForegroundColor Green

# 9) Start the agent now (don't wait for the next logon).
Start-ScheduledTask -TaskName $TaskName

Write-Host ''
Write-Host 'Done. Broker + agent will now start automatically on every boot/logon.' -ForegroundColor Cyan
Write-Host "  Broker service : $SvcName (LocalSystem, auto)"
Write-Host "  Agent task     : $TaskName (runs hidden, elevated, at logon)"
Write-Host "  To remove      : .\uninstall.ps1"
