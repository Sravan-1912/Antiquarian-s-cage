# 14 — Desktop app (Windows installer)

Antiquarian's Cage ships as an installable Windows desktop application for Super Admins and
Admins. One installer, double-click to launch — no Python, Node, or database setup. Under the
hood it is the same product: the React console and the FastAPI backend, bundled together.

## Architecture

```
Antiquarian's Cage.exe  (Electron shell)
        │  spawns, reads the chosen port from stdout, polls /api/v1/health
        ▼
cage-backend.exe  (PyInstaller, FastAPI + uvicorn on 127.0.0.1:<random free port>)
        ├── serves the React console (SPA) on the same origin
        ├── serves /api/v1/*  and  /agent/*
        └── SQLite database + keys in %APPDATA%\AntiquariansCage
```

- **One loopback origin.** The backend serves the console and the API from the same
  `http://127.0.0.1:<port>`, so cookies and **Windows Hello passkeys work** (Electron uses
  Chromium; the RP ID is `127.0.0.1`).
- **Local data.** Everything the app stores lives under `%APPDATA%\AntiquariansCage`
  (`cage.db`, `secrets.json`, `pki/`, `anchors/`). Nothing is written to Program Files.
- **No server to run.** The backend is a child process of the app and is stopped when you quit.

## Data location & secrets

On first launch the backend creates `%APPDATA%\AntiquariansCage` and generates the app secrets
(`DATA_ENCRYPTION_KEY`, `AUDIT_HMAC_KEY`, `DEVICE_CA_KEY_PASSPHRASE`) into `secrets.json`
(permissions tightened to the current user). **These secrets are generated per install and are
never shipped in the installer.** They encrypt data at rest and sign the audit chain.

| Path | What |
|------|------|
| `%APPDATA%\AntiquariansCage\cage.db` | SQLite database (all console data) |
| `%APPDATA%\AntiquariansCage\secrets.json` | Per-install encryption/signing keys |
| `%APPDATA%\AntiquariansCage\pki\` | Device CA (issues agent certificates) |
| `%APPDATA%\AntiquariansCage\anchors\` | Signed audit anchor snapshots |

**Backup = copy the `%APPDATA%\AntiquariansCage` folder** while the app is closed. Restore =
copy it back. Losing `secrets.json` makes the encrypted data and audit chain unrecoverable, so
back it up alongside the database.

## First run

1. Launch **Antiquarian's Cage** from the Start Menu.
2. The window opens on the console. Create the first **Super Admin** and register a
   **Windows Hello passkey** (PIN, fingerprint, or face — this device becomes your key).
3. Invite an **Admin** from the console; admins see only the endpoints assigned to them, Super
   Admins see everything (RBAC + admin isolation are inherited unchanged from the web product).
4. Enrol endpoints against the app's agent URL (see "Enrolling endpoints" below).

Account recovery (lost passkey) uses the existing break-glass flow:
`python -m app.recover <email>` run against the same database — documented in the auth guide.

## Enrolling endpoints

By default the backend binds **loopback only** (`127.0.0.1`), so the console is private to this
machine. Endpoints on *other* machines can only enrol if they can reach this host's `/agent`
channel. For a single-machine demo (agent on the same PC) nothing extra is needed. For remote
endpoints, expose the agent channel deliberately — this is **off by default** and should be done
only on a trusted network or through a tunnel/reverse proxy you control. See
`documentation/13-cloud-deployment.md` for the hosted option, which is the recommended path when
friends'/colleagues' devices need to enrol over the internet.

## Building the installer

From a Windows machine with Node + npm and the backend virtualenv (`backend/.venv`) ready:

```powershell
cd desktop
.\build.ps1
```

`build.ps1` runs three steps and writes the installer to `desktop/release/`:

1. **Frontend** — `npm run build` in `frontend/` → `frontend/dist`.
2. **Backend** — PyInstaller freezes `backend/app/desktop.py` → `backend/dist/cage-backend/`
   (`cage-backend.spec`). The built `frontend/dist` is bundled inside as `spa/`, along with
   `migrations/` and `alembic.ini`.
3. **Installer** — `electron-builder --win nsis` packages the Electron shell plus the backend
   (as an extra resource) into `desktop/release/Antiquarian's Cage Setup <version>.exe` (per-user
   install, Start Menu + desktop shortcuts, no admin rights needed).

### Windows symlink note (`signAndEditExecutable`)

`package.json` sets `win.signAndEditExecutable: false`. electron-builder's `winCodeSign` tool
(used to sign and to stamp the exe's icon/version via `rcedit`) ships with macOS `.dylib`
**symlinks**; extracting it fails with *"Cannot create symbolic link: A required privilege is not
held by the client"* unless Windows **Developer Mode** is on or the build runs in an **elevated**
shell. Disabling `signAndEditExecutable` skips that tool entirely, so the installer builds on a
normal (non-elevated, non-Developer-Mode) machine. The cost: the launcher keeps the default
Electron icon and generic version metadata. To embed a custom icon/version and/or Authenticode
signature, enable Developer Mode (or run elevated), set `signAndEditExecutable: true`, add
`win.icon`, and provide `CSC_LINK`/`CSC_KEY_PASSWORD` — then rebuild.

To run the shell against an already-built backend without packaging (for development):

```powershell
cd desktop
npm install
npm start
```

## Code signing (required for distribution)

The installer and `cage-backend.exe` are **unsigned** as built here. Windows SmartScreen will
warn on first run, and some environments (Smart App Control / WDAC) may block unsigned binaries.
For real distribution, sign both with an Authenticode certificate (an EV cert avoids the
SmartScreen reputation warning):

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a `
  "backend\dist\cage-backend\cage-backend.exe"
# then build the installer; electron-builder can sign it too via CSC_LINK / CSC_KEY_PASSWORD
```

Set `CSC_LINK` (path to the `.pfx`) and `CSC_KEY_PASSWORD` in the environment before `build.ps1`
and electron-builder signs the installer automatically. Signing is **not** performed by the build
script on its own — it needs a certificate that is not part of this repository.

## What the desktop app does *not* change

- Authentication is passkey-only (WebAuthn). No passwords.
- RBAC, admin isolation, the audit chain, remote actions, and the agent protocol are identical to
  the web product — the desktop app is a packaging of the same backend, not a fork.
- The agent (`cage-agent.exe` on Windows, the Linux agent) is unchanged and enrols the same way.

## Limitations / notes

- Windows x64 only (the backend exe and Electron target are x64).
- Full end-to-end verification (install → launch → passkey → enrol) must be done on a real
  Windows 10/11 machine; it cannot be validated in a headless CI environment.
- Single-instance: launching the app again focuses the existing window instead of starting a
  second backend.
