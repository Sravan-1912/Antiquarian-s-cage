<#
  Antiquarian's Cage - TEST install on a Windows 10/11 laptop. Run in an ELEVATED PowerShell from this folder:

      Set-ExecutionPolicy -Scope Process Bypass -Force
      .\Install-CageEndpoint.ps1 -Token <enrollment token> -Server https://192.168.0.100:8443

  What it installs (everything is removed by Uninstall-CageEndpoint.ps1):
    C:\Program Files\AntiquariansCage\agent      agent source + private Python environment
    C:\ProgramData\AntiquariansCage              device identity (key protected by machine DPAPI), config, logs
    Scheduled task "AntiquariansCageAgent"       runs the agent as SYSTEM at startup (test deployment; production
                                                 uses the NT SERVICE\CageAgent service account - not yet verified)
    Lock-screen tile (only with -WithTile, and only when Smart App Control is Off)

  Requires: Python 3.13+ installed for all users from python.org, internet access (to install Python packages),
  and the laptop able to reach the server address.
#>
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$Server = 'https://192.168.0.100:8443',
    [switch]$WithTile
)
$ErrorActionPreference = 'Continue'   # native tools write to stderr; every step checks its own result
$here = $PSScriptRoot
$prog = Join-Path $env:ProgramFiles 'AntiquariansCage'
$data = Join-Path $env:ProgramData 'AntiquariansCage'
$agentDir = Join-Path $prog 'agent'
$task = 'AntiquariansCageAgent'
function Step($n, $t) { Write-Host "`n[$n] $t" -ForegroundColor Cyan }
function Fail($t) { Write-Host "STOPPED: $t" -ForegroundColor Red; exit 1 }

Step 1 'Checking this laptop'
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "  $($os.Caption) build $($os.BuildNumber)"
if ([int]$os.BuildNumber -lt 19041) { Fail 'Windows 10 2004 or newer is required.' }
$sac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
$sacText = @{ 0 = 'Off'; 1 = 'On'; 2 = 'Evaluation' }[[int]$sac]
if (-not $sacText) { $sacText = 'not present (Windows 10)' }
Write-Host "  Smart App Control: $sacText"
$py = Get-Command py.exe -ErrorAction SilentlyContinue
$python = $null
if ($py) { $python = (& py.exe -3 -c "import sys;print(sys.executable)" 2>$null) }
if (-not $python) { $python = (Get-Command python.exe -ErrorAction SilentlyContinue | Where-Object { $_.Source -notmatch 'WindowsApps' } | Select-Object -First 1).Source }
if (-not $python) { Fail 'Python not found. Install Python 3.13+ from python.org (tick "Install for all users" and "Add to PATH").' }
$ver = & $python -c "import sys;print('%d.%d'%sys.version_info[:2])"
Write-Host "  Python: $python ($ver)"
if ([version]$ver -lt [version]'3.13') { Fail 'Python 3.13 or newer is required.' }

Step 2 "Checking the server ($Server)"
$ca = Join-Path $here 'server-ca.crt'
if (-not (Test-Path $ca)) { Fail 'server-ca.crt missing from this folder.' }
$check = & $python -c "import ssl,urllib.request,sys;ctx=ssl.create_default_context(cafile=sys.argv[2]);print(urllib.request.urlopen(sys.argv[1]+'/api/v1/health',context=ctx,timeout=8).read().decode())" $Server $ca 2>&1
if ("$check" -notmatch '"ok"') { Fail "Cannot reach $Server securely: $check  (same Wi-Fi? firewall on the server PC allows TCP 8443?)" }
Write-Host '  Server reachable over verified HTTPS'

Step 3 'Copying the agent'
if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { Fail 'Already installed. Run Uninstall-CageEndpoint.ps1 first.' }
New-Item -ItemType Directory -Force $agentDir, $data | Out-Null
icacls $prog /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null
Copy-Item (Join-Path $here 'agent\*') $agentDir -Recurse -Force
Copy-Item $ca (Join-Path $data 'server-ca.crt') -Force
icacls $data /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

Step 4 'Creating a private Python environment and installing packages (needs internet, ~1 minute)'
& $python -m venv (Join-Path $agentDir '.venv')
$vpy = Join-Path $agentDir '.venv\Scripts\python.exe'
if (-not (Test-Path $vpy)) { Fail 'Could not create the Python environment.' }
& $vpy -m pip install --disable-pip-version-check --quiet -r (Join-Path $agentDir 'requirements.txt')
if ($LASTEXITCODE -ne 0) { Fail 'pip install failed (internet access?).' }

Step 5 'Enrolling this laptop (creates its device key and certificate)'
Push-Location $agentDir
& $vpy -m cage_agent --data-dir $data enroll --server $Server --token $Token --ca-bundle (Join-Path $data 'server-ca.crt') --key-scope machine
$enrolled = $LASTEXITCODE
Pop-Location
if ($enrolled -ne 0) { Fail 'Enrollment failed (token used/expired? see message above).' }

Step 6 'Starting the agent as a background task (SYSTEM, at every startup)'
$action = New-ScheduledTaskAction -Execute $vpy -Argument "-m cage_agent --data-dir `"$data`" run" -WorkingDirectory $agentDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Antiquarian's Cage agent (test install)" | Out-Null
Start-ScheduledTask -TaskName $task
Start-Sleep -Seconds 8
$state = (Get-ScheduledTask -TaskName $task).State
Write-Host "  Task state: $state"
$pipe = Test-Path '\\.\pipe\AntiquariansCageUnlock'
Write-Host "  Lock-screen relay pipe present: $pipe"
if ($state -ne 'Running') { Fail "Agent task is not running - see $data\logs" }

if ($WithTile) {
    Step 7 'Installing the lock-screen tile'
    if ($sacText -eq 'On' -or $sacText -eq 'Evaluation') {
        Write-Host "  SKIPPED: Smart App Control is $sacText - Windows would refuse to load the unsigned tile." -ForegroundColor Yellow
    } else {
        & (Join-Path $here 'tile\install.ps1') -Dll (Join-Path $here 'tile\CageCredentialProvider.dll')
    }
}
Write-Host "`nDone. This laptop now appears in the console under Endpoints." -ForegroundColor Green
Write-Host "Logs: $data\logs   Uninstall: .\Uninstall-CageEndpoint.ps1"
