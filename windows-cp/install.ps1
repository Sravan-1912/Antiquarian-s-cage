<#
  Installs the "Sign in with your phone" credential provider. RUN ONLY ON A TEST VM until it has been verified there.

  Requires: elevated PowerShell; the Cage agent running as a service on the same machine (it hosts the unlock
  relay, \\.\pipe\AntiquariansCageUnlock); the device assigned to an employee who has paired Cage Authenticator.

  Safety: the provider only ADDS a tile. Windows' password and PIN tiles stay available, so if anything goes wrong you
  can still sign in normally and run uninstall.ps1. Take a VM snapshot before installing.
#>
#Requires -RunAsAdministrator
param([string]$Dll = (Join-Path $PSScriptRoot 'out\CageCredentialProvider.dll'))
$ErrorActionPreference = 'Stop'
$clsid = '{20C827DA-2D25-4842-B92D-57FB4924F87B}'
$target = Join-Path $env:ProgramFiles 'AntiquariansCage'
if (-not (Test-Path $Dll)) { throw "Build first: $Dll not found (run build.cmd)" }

New-Item -ItemType Directory -Force $target | Out-Null
# Program Files is already admin-only for writes; make it explicit for our folder (no user can replace the DLL).
icacls $target /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null
Copy-Item $Dll (Join-Path $target 'CageCredentialProvider.dll') -Force
$installed = Join-Path $target 'CageCredentialProvider.dll'
$p = Start-Process regsvr32.exe -ArgumentList '/s', "`"$installed`"" -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "regsvr32 failed with exit code $($p.ExitCode)" }
$key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
if (-not (Test-Path $key)) { throw 'Registration did not create the credential provider key' }
$hash = (Get-FileHash $installed -Algorithm SHA256).Hash
Write-Output "Installed $installed (SHA-256 $hash)"
Write-Output 'Lock the screen (Win+L) and choose "Sign in options" -> the phone tile.'
Write-Output "Diagnostics: $env:ProgramData\AntiquariansCage\credential-provider.log"
