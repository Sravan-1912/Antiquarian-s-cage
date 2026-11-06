# Antiquarian's Cage

Endpoint management and workforce security platform: employee identity, Windows endpoint
administration (agent), security policy & compliance, and tamper-evident security operations.

> **Status: Phases 1–6 implemented** (foundation, endpoint management, security policies + compliance, remote
> administration, identity security, security operations). Phase 7 (hardening and deployment) is next. What has actually been verified is in
> `documentation/test-log.md`.

## Repository layout

```
backend/          FastAPI + SQLAlchemy 2 + Alembic (Python 3.13+)
  app/core/       config, DB, logging, security headers, rate limiting
  app/security/   Argon2id, AES-256-GCM, TOTP, tokens, permission catalogue
  app/models/     ORM models          app/services/  business logic + audit
  app/api/        routers (thin)      app/schemas/   Pydantic models
  migrations/     Alembic migrations  tests/         pytest suite
frontend/         React 19 + TypeScript + Vite + Tailwind 4 + shadcn-style UI + Recharts
infrastructure/   Dockerfiles, Nginx config, DB init/hardening, secret generator
documentation/    architecture, schema, security boundaries, Windows requirements, roadmap
agent/            Windows endpoint agent (Python, separate from the backend) — see agent/README.md
```

## Phase 1 features (implemented and tested)

| Area | What works |
|---|---|
| Bootstrap | First-run organisation + Super Admin registration; closes automatically once a user exists |
| Authentication | Email verification, login, logout, password reset, change password, invitation acceptance |
| MFA | TOTP (RFC 6238) with locally rendered QR, replay protection, AES-256-GCM-encrypted secrets |
| Sessions | Opaque server-side sessions (hashed), idle + absolute expiry, list/revoke, revoke others |
| Brute force | Per-IP rate limits, per-account lockout, lockout notifications, uniform error responses |
| RBAC | 23 permissions, 5 built-in roles, enforced in backend dependencies; denials audited |
| Administrators | Invite, change role, disable/enable, unlock, revoke sessions; last Super Admin protected |
| Employees | Create, edit, joiner/mover/leaver workflows, suspend/reactivate/offboard, history, CSV export |
| Audit | Append-only hash chain + HMAC, integrity verification, filters, CSV export, PG trigger blocks UPDATE/DELETE |
| Dashboard | Real DB aggregates: workforce, sign-ins, MFA coverage, departments, joiners, activity timeline |
| Shell | Sidebar, global search (Ctrl K, permission-filtered), notification centre, profile menu |

## Phase 2 features (implemented)

| Area | What works |
|---|---|
| Enrollment | Single-use, short-lived tokens (shown once, stored hashed, optional employee pre-assignment, revocable) |
| Device identity | Agent-generated P-256 key (DPAPI-protected), CSR → certificate from internal device CA, CN = server UUID |
| Agent auth | Every request signed (timestamp ±5 min, single-use nonce, body hash) + mTLS at Nginx in production |
| Heartbeat | Online/offline derived only from authenticated heartbeats with configurable interval/threshold |
| Inventory | OS/build/edition, manufacturer/model/serial, CPU, RAM, disks, NICs/IPs/MACs, security-state reporting |
| Lifecycle | Suspend, reactivate, revoke credentials (immediate), unenrol, assign employee / IT-support owner, history |
| Certificates | List per device, automatic renewal within 30 days of expiry, old key rejected after renewal |
| Console | Endpoints list/filters/CSV, device detail (hardware, disks, network, security, certs, heartbeats, history), dashboard endpoint KPIs + enrollment, online/offline and OS charts, employee → device links |

## Phase 3 features (implemented)

| Area | What works |
|---|---|
| Policy engine | 7 categories (firewall, BitLocker, USB, antivirus, screen lock, Windows Update, password) with strict schemas, versions, revision history, one policy per category per endpoint |
| Deployment | Signed (Ed25519), expiring, single-use command jobs; pull delivery; statuses pending / in progress / applied / failed / offline / needs attention / revoked; retry; automatic redeploy on new version |
| Safety | Agent + broker each validate signature, device, expiry, nonce, allowlist, version and configuration; no shell execution; previous state recorded; rollback via signed `policy.remove`; emergency revocation |
| Privileged broker | Separate process/service, named pipe with restrictive DACL, owns rollback state, idempotent results |
| Compliance | 12 checks (PASS/FAIL/UNKNOWN/N/A), configurable severity/enablement, device + org scores, history, remediation advice; UNKNOWN never counts as compliant |
| Console | Policies list/create/edit/assign/unassign/rollback/retry/revoke, deployment details, Compliance overview/history/settings, device compliance + deployments, dashboard compliance distribution, deployment outcomes and security trend |

See `documentation/06-policy-recovery.md` for rollback and manual recovery per policy.

## Phase 4 features (implemented)

| Area | What works |
|---|---|
| Remote actions | Status inspection, lock, restart (warned, cancellable), cancel restart, disable/enable local account, remove from Administrators — signed, allowlisted, schema-checked by server, agent and broker; password re-entry for sensitive actions; last-admin protection |
| Remote assistance | Consent prompt by default (auto-decline), always-on-top indicator with End button, Quick Assist launched only after consent, maximum duration, termination from either side, server + endpoint expiry, verified cleanup with privileged fallback, full audit trail |
| Console | Remote administration panel and local-accounts view per endpoint, action and session history, Remote sessions page, organisation remote-assistance policy (consent, max duration, IT Support access) |

Details and limitations: `documentation/07-remote-administration.md`.

## Phase 5 features (implemented)

| Area | What works |
|---|---|
| Employee accounts | Workspace invitation (Employee role), My workspace (apps + devices), suspend/reactivate, leaver revokes sessions, SSO grants and passkeys |
| Passkeys | WebAuthn registration/sign-in (usernameless, user verification required, counts as MFA), naming, removal, admin revocation |
| SSO (OIDC provider) | Discovery, JWKS, authorization code + mandatory PKCE, RS256 ID/access tokens, userinfo, per-app MFA step-up, exact redirect matching, assignment checks at every step, authentication events per app |
| Applications | Register confidential/public clients, secret shown once and stored hashed, rotation, enable/disable, assignments, "verified" only after a real sign-in |

Details: `documentation/08-identity-and-sso.md`. A sample relying party for testing lives in `infrastructure/samples/`.

## Phase 6 features (implemented)

| Area | What works |
|---|---|
| Alerts | 12 detection rules (sign-in bursts, password spraying, success after failures, firewall/antivirus/BitLocker, USB storage, agent silence, deployment failures, admin bursts, permission denials, remote-access anomalies); kinds configuration/operational/suspicious; de-duplication; auto-resolution |
| Investigation | Queue with filters, assignment to analysts, status workflow, required resolution notes, history, audit |
| Notifications | Categories with per-user in-app/email thresholds, durable email outbox with retries, scheduler (advisory-locked) |
| Reports | 8 reports as CSV or PDF from live data, permission-scoped, exports audited |
| Dashboard | Critical/open alert KPIs, severity distribution, alerts per day |

Details: `documentation/09-security-operations.md`.

## Local development

Prerequisites: Python 3.13+ (3.14 tested), Node 22+ (26 tested), **PostgreSQL 16** (or SQLite for a quick look).

```bash
cd backend
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt     # Windows; use .venv/bin on Linux/macOS
cp ../.env.example .env                                 # then fill in the values
python ../infrastructure/scripts/generate_secrets.py   # paste DATA_ENCRYPTION_KEY / AUDIT_HMAC_KEY into .env
.venv/Scripts/alembic upgrade head
.venv/Scripts/uvicorn app.main:app --reload --port 8000
```

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173 (proxies /api to :8000)
```

Open http://localhost:5173 — the first visit goes to **Set up your organisation**. Without SMTP configured,
development mode writes emails (verification / reset / invite links) as `.eml` files to `backend/var/outbox/`.

### Tests

```bash
cd backend && .venv/Scripts/python -m pytest -q          # SQLite by default
TEST_DATABASE_URL=postgresql+psycopg://user:pw@localhost/cage_test pytest -q   # same suite on PostgreSQL
cd frontend && npm test && npm run typecheck && npm run build
```

## Docker deployment

```bash
cp .env.example .env && python infrastructure/scripts/generate_secrets.py >> .env   # edit duplicates
# place TLS cert/key at infrastructure/nginx/certs/console.crt|console.key
docker compose up -d --build
docker compose exec postgres psql -U cage_owner -d antiquarians_cage -f /dev/stdin < infrastructure/scripts/harden_db.sql
```

The API connects as the least-privilege `cage_app` role; migrations run as `cage_owner`.

## Current verification status (2026-11-06)

* PostgreSQL 16.15 installed locally; dev DB `antiquarians_cage` and test DB `cage_test`, schema owned by
  `cage_owner`, API running as least-privilege `cage_app` (INSERT/SELECT only on `audit_logs`).
* Backend: **60/60 pytest tests pass on PostgreSQL** (migrations as owner, API as `cage_app`), including the
  append-only audit trigger test. Also passes on SQLite.
* Frontend: typecheck, 4 Vitest tests and production build pass.
* Agent: 39 pytest tests pass (validator, broker core, named pipe, registry rollback, remote actions, assistance
  lifecycle, real collection on Windows 11).
* Phase 3 chain verified live on Windows 11 Home with an **unelevated** broker (no system changes) — see test log.
* Phase 2 verified on a real Windows 11 Home machine (enrol, heartbeat, inventory, suspend, revoke, re-enrol) —
  details and gaps in `documentation/test-log.md`.
* Manually verified in a browser against PostgreSQL: setup -> email verification -> sign-in -> dashboard ->
  invite Security Analyst -> accept invite -> analyst sign-in; direct API calls as the analyst return 403 for
  audit/users/employee-create and 200 for permitted reads; denials appear in the audit log; chain verifies.
* **Not yet verified:** policy changes applied by an *elevated* broker, broker/agent as Windows services /
  virtual service account, mTLS through Nginx, Docker Compose
  stack, Playwright E2E suite, Redis-backed rate limiting, real SMTP delivery, Windows 10/Pro/domain-joined devices.

Run the suite against PostgreSQL:

```bash
TEST_DATABASE_URL=postgresql+psycopg://cage_app:...@localhost:5432/cage_test TEST_MIGRATION_DATABASE_URL=postgresql+psycopg://cage_owner:...@localhost:5432/cage_test backend/.venv/Scripts/python -m pytest -q
```

See `SECURITY.md` for the security model and known limitations.
