<#
  Removes the phone sign-in credential provider and (with -RemoveSavedPasswords) the encrypted passwords it stored.

  Offline recovery (machine will not let you sign in at all - should not happen, the password tile is untouched):
  boot Windows Recovery -> Command Prompt, then
     reg load HKLM\OFFSOFT C:\Windows\System32\config\SOFTWARE
     reg delete "HKLM\OFFSOFT\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{20C827DA-2D25-4842-B92D-57FB4924F87B}" /f
     reg unload HKLM\OFFSOFT
#>
#Requires -RunAsAdministrator
param([switch]$RemoveSavedPasswords)
$ErrorActionPreference = 'Continue'
$clsid = '{20C827DA-2D25-4842-B92D-57FB4924F87B}'
$dll = Join-Path $env:ProgramFiles 'AntiquariansCage\CageCredentialProvider.dll'
if (Test-Path $dll) { Start-Process regsvr32.exe -ArgumentList '/u', '/s', "`"$dll`"" -Wait | Out-Null }
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -Recurse -ErrorAction SilentlyContinue
# LogonUI may still hold the DLL; it is removed at the next restart if locked now.
Remove-Item $dll -Force -ErrorAction SilentlyContinue
if ($RemoveSavedPasswords) {
    Remove-Item 'HKLM:\SOFTWARE\AntiquariansCage\PhoneUnlock' -Recurse -ErrorAction SilentlyContinue
    Write-Output 'Removed saved (encrypted) passwords. Also remove the setups in the console (endpoint page).'
}
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid") {
    Write-Error 'Provider is still registered'
    exit 1
}
Write-Output 'Phone sign-in tile removed.'
