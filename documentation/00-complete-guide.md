# Antiquarian's Cage — Complete Guide

A single entry point to the whole platform: what it is, how it is built, how to run and operate it, and how the
passkey-only sign-in works end to end. Deep dives live in the numbered documents referenced throughout; this guide ties
them together and is kept current with the latest changes.

> **Last updated: 2026-11-11.** Reflects **Phase 13 — passkey-only authentication**. There are **no passwords and no
> TOTP** anywhere in the product; the only interactive sign-in is a WebAuthn passkey with user verification.

---

## 1. What it is

Antiquarian's Cage is an enterprise **endpoint-management and workforce-security** platform:

- **Identity & access** — administrators and employees, RBAC with admin isolation, WebAuthn passkeys, an OIDC provider
  for single sign-on into other apps.
- **Endpoint management** — a Windows agent enrolls with a device certificate, reports inventory and heartbeats, and
  runs **signed, allowlisted** jobs through an elevated broker.
- **Security policy & compliance** — seven policy categories applied and verified on endpoints, with a tri-state
  compliance engine (UNKNOWN is never counted as compliant).
- **Remote administration** — lock, restart, local-account changes and consented remote assistance, each signed and
  requiring a fresh passkey step-up.
- **Security operations** — detection rules, alerts, notifications (in-app / email / WebSocket), CSV/PDF reports, and a
  tamper-evident audit chain anchored to external storage.
- **Phone & Windows unlock** — a Cage Authenticator Android app pairs a biometric-bound key used to approve **Windows
  laptop unlock** from the phone.

### Components

| Component | Stack | Location |
|---|---|---|
| Backend API | FastAPI + SQLAlchemy 2 + Alembic, Python 3.13+ | `backend/` |
| Frontend console + workspace | React 19 + TypeScript + Vite + Tailwind 4 | `frontend/` |
| Windows endpoint agent + broker | Python (PyInstaller), split agent/broker | `agent/` |
| Cage Authenticator app | Expo / React Native (SDK 58) | `mobile/` |
| Windows credential provider | C++ / MSVC (COM `ICredentialProvider`) | `windows-cp/` |
| Infra | Docker, Nginx, DB init/hardening, secret generator | `infrastructure/`, `docker-compose.yml` |

---

## 2. Phase status (1–13)

| Phase | Area | Status |
|---|---|---|
| 1 | Foundation (auth, RBAC, audit chain, dashboard, employees/JML) | Complete, verified on PostgreSQL |
| 2 | Endpoint management (agent, device CA, mTLS, heartbeat, inventory, lifecycle) | Implemented; verified on a real Windows 11 Home machine |
| 3 | Security policy + compliance (7 categories, signed jobs, broker) | Implemented; screen-lock apply/rollback verified live |
| 4 | Remote administration (lock, restart, consented assistance) | Implemented; consented-assist flow verified live |
| 5 | Identity security (passkeys, OIDC provider, app assignments) | Implemented; SSO verified live — **superseded by Phase 13 for sign-in** |
| 6 | Security operations (alerts, notifications, reports) | Implemented; verified live on real endpoint data |
| 7 | Hardening (DB roles/RLS, audit anchors, backup/restore, preflight) | Complete for everything verifiable off-cluster |
| 8 | Cage Authenticator (phone pairing + signed approvals) | Implemented; APK built locally |
| 9 | Fleet overview + real network usage | Implemented |
| 10 | Windows phone unlock (credential provider + SYSTEM broker) | **Built, awaiting Windows 10/11 test-VM verification** |
| 11 | Admin isolation (Super Admin vs scoped Admin) | Implemented; proven by tests |
| 12 | Subscription tiers + device-slot quotas | Implemented; proven by tests |
| 13 | **Passkey-only auth** (remove passwords + TOTP) | Implemented; backend suite green on SQLite, frontend builds clean |

**Not done / declined:** Windows EV code-signing of agent binaries (#4) and legitimate Android APK signing (#5) are
outstanding; Play Protect / AV-evasion (part of #5) was **declined** and will not be done. PostgreSQL test-matrix run
and a manual browser passkey bootstrap for Phase 13 are still pending. See `04-roadmap.md` for the full detail.

---

## 3. Authentication: passkey-only (how it works)

There are no passwords and no TOTP. A passkey with user verification already combines **possession** (the authenticator)
with a **biometric/PIN**, so it is MFA on its own. Because you cannot register a passkey without first proving who you
are, every "set your credential" moment is a **single-use, short-lived token that drives a passkey registration
ceremony**:

| Moment | Endpoint(s) | What happens |
|---|---|---|
| First-run bootstrap | `POST /auth/register` → `/auth/enroll/{options,verify}` | Creates the org + first Super Admin (`pending`), returns an enrol token, ceremony registers the first passkey and signs in |
| Invitation | `POST /users` → emailed `/accept-invite` link → `/auth/enroll/*` | Invite link doubles as a passkey-enrol token |
| Admin-issued recovery | `POST /users/{id}/recovery` (perm `users:manage`) → `/recover` link | Revokes the user's old passkeys, enrols a new one |
| Break-glass | `python -m app.recover <email>` (host/DB access) | Mints a recovery link for a sole Super Admin who lost every passkey |
| Normal sign-in | `POST /auth/passkeys/login/{options,verify}` | Usernameless; py_webauthn verifies the assertion against the stored public key |
| Sensitive remote action | `POST /auth/step-up/options` + assertion | Fresh passkey confirmation (step-up), no session grant |

Tokens are stored hashed, single-use, consumed on success. A failed passkey assertion is rate-limited (per-IP and
per-account via the retained `failed_login_count` / `locked_until`) and feeds the security-operations detection rules.
Only public keys, credential IDs, sign counters and metadata are stored — biometrics never leave the authenticator.

**Recovery safety:** register a **second passkey** (a different device or a security key) right after bootstrap. The
break-glass CLI is the last resort for a sole Super Admin; guard host access accordingly. Full detail and the OIDC
provider are in `08-identity-and-sso.md`; recovery procedures are in `10-operations-runbook.md`.

> The former phone-approval **console sign-in** (Phase 8) was removed with Phase 13. A phone is still a first-class
> console passkey via standard WebAuthn (platform or cross-device/hybrid). Phone **pairing** is kept and now drives
> **Windows laptop unlock only** (`12-windows-phone-unlock.md`).

---

## 4. Running it

### 4a. Full stack with Docker (closest to production)

```bash
python infrastructure/scripts/generate_secrets.py   # write values into .env (never commit)
docker compose up -d --build
```

The `migrate` service runs `alembic upgrade head` as the schema owner; the `api` service then runs as a least-privilege
role. Services: `postgres` (16), `redis` (7), `migrate`, `api`, `web` (Nginx). First real deployment (offline keys,
TLS, DB hardening) is in `10-operations-runbook.md`.

### 4b. Local development

Backend (from `backend/`, with a virtualenv and a reachable PostgreSQL or SQLite):

```bash
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Frontend (from `frontend/`):

```bash
npm install
npm run dev
```

Open the console, which on first run sends you to **Set up your organisation** → passkey ceremony → dashboard. Use a
platform authenticator (Windows Hello / Touch ID) or a browser **virtual authenticator** (DevTools → WebAuthn) if the
machine has none.

### 4c. Agent (Windows endpoint)

Build with the PyInstaller specs in `agent/` (`cage-agent*.spec`, `cage-broker*.spec`); installer assets are under
`agent/installer/`. Enrol with a single-use token minted in the console. See `agent/README.md` and
`03-security-and-windows.md`.

### 4d. Cage Authenticator app

```bash
cd mobile
npm install
./build-android.ps1        # builds a signed APK locally
```

iOS project config is written but an `.ipa` needs a Mac / Apple account. The app only does **pairing** and **Windows
unlock approval** — no console login.

---

## 5. Testing

```bash
# Backend (from backend/)
python -m pytest -q                               # SQLite by default
TEST_DATABASE_URL=postgresql+psycopg://… python -m pytest -q   # PostgreSQL matrix

# Frontend (from frontend/)
npm run build        # tsc -b + vite build (typecheck + bundle)
npm run test         # Vitest
npm run e2e          # Playwright

# Backend production-config sanity
python -m app.preflight
```

Tests use real `py_webauthn` with a software authenticator (`SoftAuthenticator` in `tests/conftest.py`), so passkey
sign-in, enrolment, recovery and step-up are exercised end to end without a device. Helpers: `bootstrap_admin`,
`invite_and_accept`, `login`, `step_up`. **Last run:** backend green on SQLite (93 passed, 2 skipped); frontend
typecheck + build clean. The PostgreSQL matrix is still to be run on this machine.

> **Windows note:** if `pytest` fails to collect with `DLL load failed while importing _pydantic_core: An Application
> Control policy has blocked this file`, that is Windows **Smart App Control / WDAC** blocking the compiled extension,
> not a code problem. Clear the mark-of-the-web on the venv's `.pyd` files (e.g. `Get-ChildItem -Recurse
> .venv\Lib\site-packages -Filter *.pyd | Unblock-File`) or allow the Python toolchain in the Windows security policy,
> then re-run.

---

## 6. Operations & security

- **Audit** — append-only hash chain + HMAC, verified on read, exported to WORM/external anchor storage; a PostgreSQL
  trigger blocks UPDATE/DELETE. See `09-security-operations.md`.
- **Sessions** — 256-bit opaque tokens in `HttpOnly; SameSite=Strict; Secure` cookies (only hashes stored); idle (30m)
  and absolute (12h) expiry; revoked on logout, passkey revocation, role change, disable, suspension. Double-submit
  CSRF + Origin allow-list on state-changing requests.
- **RBAC + admin isolation** — Super Admin unrestricted (`tenant:global`); Admin scoped to assigned users/endpoints via
  `owner_admin_id`; standard users have no console.
- **Device quotas** — per-org `max_device_slots` enforced at enrollment (HTTP 402).
- **Remote actions** — allowlisted, signed, schema-checked by server/agent/broker; sensitive ones need a fresh passkey
  step-up; the last enabled local admin cannot be disabled/demoted.
- **Recovery / break-glass / incident playbooks** — `10-operations-runbook.md`.
- **Threat model & Windows trust boundaries** — `03-security-and-windows.md`; summary in `SECURITY.md`.

---

## 7. Document map

| Doc | Covers |
|---|---|
| `01-architecture.md` | System architecture and request flow |
| `02-database-schema.md` | ORM models and schema |
| `03-security-and-windows.md` | Threat model, agent/broker trust boundaries |
| `04-roadmap.md` | Phases 1–13, status, risks, testing requirements |
| `06-policy-recovery.md` | Policy engine and recovery |
| `07-remote-administration.md` | Remote actions and consented assistance |
| `08-identity-and-sso.md` | **Passkey-only sign-in**, passkeys, OIDC provider |
| `09-security-operations.md` | Alerts, notifications, audit anchoring |
| `10-operations-runbook.md` | Deploy, backup/restore, recovery, incidents |
| `11-phone-sign-in-and-fleet-overview.md` | Fleet overview (phone **console** sign-in marked removed) |
| `12-windows-phone-unlock.md` | Windows credential provider + phone unlock |
| `api/openapi.json` | Generated OpenAPI schema (passkey-only surface) |
| `test-log.md` | What has actually been verified, with evidence |

---

## 8. Known limitations (current)

- **Phase 10** (Windows phone unlock) is built and tested off the lock screen but **not yet verified on a Windows 10/11
  test VM**.
- **Phase 13** PostgreSQL test matrix and a manual browser passkey bootstrap are still to be run.
- **Agent/app binary signing** (#4 Windows EV, #5 Android) is outstanding; AV/Play-Protect evasion was declined.
- Agent production-readiness items remain: service install with machine-scope key, mTLS through Nginx, and coverage of
  Windows 10 / Pro / Enterprise / domain-joined devices.

Only what is recorded in `test-log.md` has actually been verified end to end; everything else is "implemented and
unit/integration-tested" unless this guide says otherwise.
