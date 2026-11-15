# Build the Antiquarian's Cage desktop installer end to end.
#
#   1. build the React console          (frontend/dist)
#   2. freeze the backend to an exe      (backend/dist/cage-backend/)
#   3. package the Electron app + NSIS   (desktop/release/*.exe)
#
# Run from the desktop/ folder:  .\build.ps1
# Requires: Node + npm, the backend venv at backend/.venv, PyInstaller in that venv.

$ErrorActionPreference = "Stop"
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
Step "Packaging the desktop app (electron-builder)"
Push-Location $desktop
if (-not (Test-Path "node_modules")) { npm install }
npm run dist
Pop-Location

Step "Done"
Write-Host "Installer written to: $(Join-Path $desktop 'release')" -ForegroundColor Green
