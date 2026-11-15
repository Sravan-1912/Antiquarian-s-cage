# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build of the desktop backend.

Entry point: app/desktop.py (first-run bootstrap + uvicorn). Produces an onedir bundle
`dist/cage-backend/cage-backend.exe` that Electron spawns as an extraResource.

Bundled resources (resolved at runtime via sys._MEIPASS):
  * migrations/ + alembic.ini  -> Alembic upgrade on launch
  * ../frontend/dist -> spa/    -> the console SPA served same-origin

Build:  .venv\\Scripts\\pyinstaller.exe cage-backend.spec --noconfirm
"""
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

hiddenimports = []
hiddenimports += collect_submodules("uvicorn")      # loops/protocols selected at runtime by string
hiddenimports += collect_submodules("app")          # app.main etc. imported by uvicorn as "app.main:app"
hiddenimports += ["anyio", "email_validator", "passlib.handlers.argon2"]

datas = [
    ("migrations", "migrations"),
    ("alembic.ini", "."),
    ("../frontend/dist", "spa"),
]
datas += collect_data_files("webauthn")             # py_webauthn metadata/assets

a = Analysis(
    ["app/desktop.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "pytest", "IPython"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="cage-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,            # Electron reads the "CAGE_READY port=..." line from stdout
    disable_windowed_traceback=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="cage-backend",
)
