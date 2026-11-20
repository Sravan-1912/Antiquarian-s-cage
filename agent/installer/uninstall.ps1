<#
.SYNOPSIS
    Remove the Antiquarian's Cage auto-start (agent logon task + broker service) installed by install.ps1.
    Run from an ELEVATED PowerShell.

.PARAMETER InstallDir
    Where the exes were installed. Default: "$env:ProgramFiles\AntiquariansCage".

.PARAMETER Purge
    Also delete the data directory ("$env:ProgramData\AntiquariansCage": device key, config, broker pin).
    Revoke/unenrol the device in the console first.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AntiquariansCage'),
    [string]$DataDir    = (Join-Path $env:ProgramData 'AntiquariansCage'),
    [switch]$Purge
)

$ErrorActionPreference = 'Continue'
$TaskName = 'AntiquariansCageAgent'
$SvcName  = 'CageBroker'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an ELEVATED PowerShell (Run as administrator).'
}

Write-Host '== Antiquarian''s Cage: removing auto-start ==' -ForegroundColor Cyan

# 1) Stop + remove the agent logon task, then kill any running agent.
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "  Removed logon task '$TaskName'." -ForegroundColor Green
}
Get-Process -Name 'cage-agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# 2) Stop + remove the broker service.
$brokerService = Join-Path $InstallDir 'cage-broker-service.exe'
if (Get-Service -Name $SvcName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $brokerService) { & $brokerService remove | Out-Null }
    else { & sc.exe delete $SvcName | Out-Null }
    Write-Host "  Removed broker service '$SvcName'." -ForegroundColor Green
}

# 3) Remove installed exes (keep the data dir unless -Purge).
if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Removed $InstallDir." -ForegroundColor Green
}
if ($Purge -and (Test-Path -LiteralPath $DataDir)) {
    Remove-Item -LiteralPath $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Purged data dir $DataDir." -ForegroundColor Yellow
}

Write-Host 'Done.' -ForegroundColor Cyan
