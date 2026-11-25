# Build the Antiquarian's Cage desktop installer end to end.
#
#   1. build the React console          (frontend/dist)
#   2. freeze the backend to an exe      (backend/dist/cage-backend/)
#   3. package the Electron app + NSIS   (desktop/release/*.exe)
#
# Run from the desktop/ folder:  .\build.ps1
# Requires: Node + npm, the backend venv at backend/.venv, PyInstaller in that venv.

# NOTE: 'Continue', not 'Stop' — native tools here (Vite, PyInstaller) print warnings to stderr, which under
# 'Stop' PowerShell 5.1 turns into a fatal NativeCommandError. Each stage below validates its real output
# (Test-Path / $LASTEXITCODE) and throws on genuine failure, so warnings no longer abort the build.
$ErrorActionPreference = "Continue"
$desktop = $PSScriptRoot
$root    = Split-Path $desktop -Parent
$frontend = Join-Path $root "frontend"
$backend  = Join-Path $root "backend"
$venvPy   = Join-Path $backend ".venv\Scripts\python.exe"

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# 1. Frontend -----------------------------------------------------------------------------------
Step "Building the console (frontend)"
Push-Location $frontend
if (-not (Test-Path "node_modules")) { npm ci }
npm run build
Pop-Location
if (-not (Test-Path (Join-Path $frontend "dist\index.html"))) { throw "frontend build produced no dist/index.html" }

# 2. Backend exe --------------------------------------------------------------------------------
Step "Freezing the backend (PyInstaller)"
if (-not (Test-Path $venvPy)) { throw "backend venv not found at $venvPy" }
Push-Location $backend
& $venvPy -m pip install --quiet "pyinstaller==6.22.3"
& $venvPy -m PyInstaller cage-backend.spec --noconfirm --distpath dist --workpath build
Pop-Location
if (-not (Test-Path (Join-Path $backend "dist\cage-backend\cage-backend.exe"))) { throw "backend exe not produced" }

# 3. Electron installer -------------------------------------------------------------------------
# electron-builder's own exe-icon/version editing (signAndEditExecutable) pulls winCodeSign, whose
# archive contains macOS symlinks that 7-Zip cannot extract on Windows without Developer Mode or
# elevation. So signAndEditExecutable is false in package.json and we do it ourselves: package to an
# unpacked dir, stamp the brand icon onto the app exe with the vendored rcedit, then build the NSIS
# installer from that already-packaged dir (--prepackaged skips the pack+edit step, so no winCodeSign).
Step "Packaging the desktop app (electron-builder)"
Push-Location $desktop
if (-not (Test-Path "node_modules")) { npm install }
& ".\node_modules\.bin\electron-builder" --win --dir
$appExe = Join-Path $desktop "release\win-unpacked\Antiquarian's Cage.exe"
if (-not (Test-Path $appExe)) { throw "packaging produced no app exe" }
Step "Stamping the app icon (rcedit)"
& (Join-Path $desktop "tools\rcedit-x64.exe") $appExe --set-icon (Join-Path $desktop "build\icon.ico")
if ($LASTEXITCODE -ne 0) { throw "rcedit failed to set the app icon" }
Step "Building the installer (NSIS, from the packaged dir)"
& ".\node_modules\.bin\electron-builder" --win nsis --prepackaged "release\win-unpacked"
Pop-Location

Step "Done"
Write-Host "Installer written to: $(Join-Path $desktop 'release')" -ForegroundColor Green
