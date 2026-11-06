# Builds the agent executables with PyInstaller. Run from the agent directory:
#   .\.venv\Scripts\Activate.ps1; .\installer\build.ps1
# Output: dist\cage-agent.exe (CLI) and dist\cage-agent-service.exe (service host).
# Production builds must be Authenticode-signed before distribution (signtool sign /fd sha256 ...).
# Note: PyInstaller logs to stderr, so success is judged by exit code, not by ErrorActionPreference.
Set-Location (Split-Path $PSScriptRoot -Parent)

function Invoke-Build([string[]]$PyArgs) {
    & pyinstaller @PyArgs 2>&1 | Out-File -Append -Encoding utf8 build\pyinstaller.log
    if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed ($LASTEXITCODE); see build\pyinstaller.log" }
}

New-Item -ItemType Directory -Force build | Out-Null
Remove-Item build\pyinstaller.log -ErrorAction SilentlyContinue
Invoke-Build @('--noconfirm', '--clean', '--onefile', '--name', 'cage-agent', '--paths', '.', 'cage_agent\__main__.py')
Invoke-Build @('--noconfirm', '--clean', '--onefile', '--name', 'cage-agent-service', '--paths', '.',
               '--hidden-import', 'win32timezone', 'installer\service.py')
Invoke-Build @('--noconfirm', '--clean', '--onefile', '--name', 'cage-broker', '--paths', '.', 'cage_broker\__main__.py')
Invoke-Build @('--noconfirm', '--clean', '--onefile', '--name', 'cage-broker-service', '--paths', '.',
               '--hidden-import', 'win32timezone', 'installer\broker_service.py')
Get-FileHash dist\*.exe -Algorithm SHA256 | Format-Table -AutoSize
