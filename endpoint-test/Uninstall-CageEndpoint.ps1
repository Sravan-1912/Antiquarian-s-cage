<#
  Removes everything Install-CageEndpoint.ps1 added. Run in an ELEVATED PowerShell from this folder:
      Set-ExecutionPolicy -Scope Process Bypass -Force
      .\Uninstall-CageEndpoint.ps1
  Afterwards: in the console, open the endpoint and click "Unenroll" (or "Revoke") so its certificate stops working.
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Continue'
$prog = Join-Path $env:ProgramFiles 'AntiquariansCage'
$data = Join-Path $env:ProgramData 'AntiquariansCage'
$task = 'AntiquariansCageAgent'
$problems = @()

Write-Host '[1] Removing the lock-screen tile and saved (encrypted) passwords'
& (Join-Path $PSScriptRoot 'tile\uninstall.ps1') -RemoveSavedPasswords

Write-Host '[2] Stopping and removing the agent task'
if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
}
Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" | Where-Object { $_.CommandLine -match 'cage_agent' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { $problems += 'scheduled task still present' }

Write-Host '[3] Deleting program files, device identity and logs'
foreach ($p in @($prog, $data)) {
    if (Test-Path $p) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $p) { $problems += "$p could not be fully deleted (in use? restart and run again)" }
    }
}
if ($problems) {
    Write-Host "Finished with problems:`n - $($problems -join "`n - ")" -ForegroundColor Yellow
    exit 1
}
Write-Host 'Antiquarian''s Cage removed from this laptop.' -ForegroundColor Green
Write-Host 'Remaining manual steps: unenroll the endpoint in the console; delete the test Windows account if you created one;'
Write-Host 'uninstall Python from Settings > Apps if it was installed only for this test.'
