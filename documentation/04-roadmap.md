# Development Roadmap, Risks & Testing

## Phases

| Phase | Scope | Exit criteria |
|---|---|---|
| 1 Foundation | Repo, design system, admin auth, RBAC, audit chain, dashboard (real queries), employees + JML | Backend + frontend run against PostgreSQL; pytest green; registration/sign-in/RBAC verified manually |
| 2 Endpoint mgmt | Agent skeleton, enrollment tokens, device CA, mTLS, heartbeat, inventory, lifecycle ops | Agent enrolled on a Windows VM; heartbeat/offline transitions observed; cert revocation blocks agent |
| 3 Security mgmt | Policy engine, 7 policy categories, signed jobs, broker service, compliance engine (12 checks) | Each policy applied & rolled back on a VM; UNKNOWN never counted compliant |
| 4 Remote admin | Lock, restart, consented assistance sessions, session expiry | Consent prompt + indicator verified; denial path verified |
| 5 Identity security | Employee sign-in, WebAuthn passkeys, OIDC provider, app assignments | Passkey round trip in Chrome/Edge; OIDC login tested against a sample relying party |
| 6 SecOps | Alert rules, alert workflow, notifications (in-app/email/WS), reports CSV/PDF | Each detection triggered by a reproducible scenario |
| 7 Hardening | DB roles/RLS, audit anchor export, load tests, backup/restore drill, threat-model review, pentest checklist | Documented results |
| 8 Phone authenticator | Cage Authenticator Android app; biometric-bound key pairing | Pairing + signed approval verified; APK built and installed |
| 9 Fleet overview | Real network-usage counters from the agent; dashboard redesign | Byte counters and overview render from live agent data |
| 10 Windows phone unlock | Windows credential provider + SYSTEM broker relay; approve laptop unlock from the phone | Built and tested off the lock screen; awaiting Windows 10/11 test-VM verification |
| 11 Admin isolation | Super Admin unrestricted; Admin scoped to assigned users/endpoints via `owner_admin_id` + `tenant:global` | Two admins proven isolated; Super Admin sees all (pytest) |
| 12 Subscriptions & quotas | Subscription tiers; `max_device_slots` enforced at enrollment (HTTP 402) | Quota blocks over-enrolment; Super Admin org-level unlimited |
| 13 Passkey-only auth | Remove passwords (Argon2id) and TOTP; passkeys the only sign-in; token-driven onboarding/recovery; break-glass CLI | Full suite migrated to passkey login; passwords/TOTP columns dropped (migration 0013) |

## Status (2026-11-11)

* **Phase 1 — complete**, verified on PostgreSQL 16.
* **Phase 2 — implemented**, verified on one real Windows 11 Home machine (see `test-log.md`). Open items before
  calling it production-ready: service install as `NT SERVICE\CageAgent` with machine-scope key, mTLS through Nginx,
  Windows 10 / Pro / Enterprise / domain-joined devices, signed agent binaries and secure self-update.
* **Phase 3 — implemented**, chain verified live; screen-lock apply + exact rollback verified with an elevated broker on
  Windows 11 Home. Before calling it production-ready: verify the other six policies' apply + rollback with an elevated
  broker on an isolated VM (Home, Pro and Enterprise editions), USB allowlist on Pro/Enterprise, broker/agent as services, signed key rotation.
* **Phase 4 — implemented**; status inspection and the consented assistance flow verified live (consent →
  indicator → Quick Assist → console termination), which exposed and led to fixing the Quick Assist cleanup. Before
  production: verify broker cleanup, lock, restart and account actions on an isolated VM, and implement the
  user-session helper launch for service mode.
* **Phase 5 — implemented**; real SSO verified live against an independent relying party; passkeys verified by
  automated tests with a software authenticator, but a live Windows Hello registration has not been completed yet.
  SAML not implemented. (Superseded by Phase 13: passkeys are now the *only* console sign-in.)
* **Phase 6 — implemented**; alert detection, email outbox delivery and reports verified live on real endpoint data.
  The agent-silence alert and the heartbeat-retention purge (previously deferred) now run in the scheduler.
* **Phase 7 — complete** for everything verifiable on this machine: security review, audit anchoring, N+1 fixes
  with a scaling test, Playwright E2E, encrypted backup + restore drill, production guards + preflight, runbook,
  OpenAPI export. Not verifiable here: Docker stack, Nginx mTLS, Redis, SMTP (see `10-operations-runbook.md`).
* **Phase 8 — implemented**; the Cage Authenticator Android app pairs a biometric-bound key and signs approvals. A
  signed APK is built locally (`mobile/build-android.ps1`); the iOS project is written but `.ipa` needs a Mac/Apple
  account. _The phone-approval **console sign-in** this phase introduced was removed in Phase 13 (passkey-only); phone
  pairing is kept for Windows unlock._
* **Phase 9 — implemented**; real network-usage counters from the agent and the redesigned fleet overview render on
  live data.
* **Phase 10 — built, awaiting VM verification**; Windows credential provider + SYSTEM broker relay approve a laptop
  unlock from the paired phone. Tested off the lock screen; still to be verified on a Windows 10/11 test VM
  (`12-windows-phone-unlock.md`).
* **Phase 11 — implemented**; admin isolation (`owner_admin_id` + `tenant:global`): Super Admin unrestricted, Admin
  scoped to assigned users/endpoints, standard users have no console. Proven by `test_admin_isolation.py`.
* **Phase 12 — implemented**; subscription tiers and per-org device-slot quotas enforced at enrollment (HTTP 402),
  Super Admin org-level unlimited. Covered by `test_subscriptions.py`.
* **Phase 13 — implemented**; **passkey-only authentication**. Passwords (Argon2id) and TOTP removed entirely;
  bootstrap, invitation and admin-issued recovery each run a single-use token → passkey registration ceremony; a
  break-glass CLI (`python -m app.recover`) recovers a sole Super Admin; sensitive remote actions use a fresh passkey
  step-up. Migration 0013 drops the password/MFA columns. Full backend suite migrated to passkey login and last run
  green on SQLite (93 passed, 2 skipped); frontend typecheck + build clean. PostgreSQL matrix and a manual browser
  bootstrap still to be run.
* **Remaining from the signing/hardening spec:** #4 Windows EV code signing of the agent binaries and #5 legitimate
  Android APK signing (Play Protect / AV-evasion was declined and will not be done).
* (Historical note) Deferred to Phase 6 by design: an alert/notification when an agent *stops* reporting (offline is already computed
  and shown; the alerting rule engine does not exist yet) and the scheduled heartbeat-retention purge job
  (`services.devices.purge_old_heartbeats` exists, the Celery schedule does not).

## Key risks

| Risk | Impact | Mitigation |
|---|---|---|
| Agent running with excessive privilege | Endpoint takeover if agent exploited | Split agent/broker, LocalService, allowlist |
| Server compromise used to push malicious commands | Fleet-wide compromise | Offline/HSM-held command signing key, allowlist on agent, no shell execution |
| Unknown checks treated as pass | False sense of security | Tri-state + explicit tests |
| Scope creep (full RDP stack, SAML IdP) | Delivery slip | Integrate standards/OS tooling, phase gates |
| Insider admin abuse | Data/device misuse | RBAC + admin isolation, audit chain with external key, fresh-passkey step-up for sensitive ops |
| Python agent footprint | Performance, AV false positives | PyInstaller signed builds; consider Rust/Go rewrite of broker later |

## Testing requirements

* **Backend (pytest)**: unit tests for WebAuthn passkey verification (real py_webauthn via a software authenticator),
  AES-GCM crypto, CSRF, permission resolution, audit chain verification; API tests for passkey sign-in / enrolment /
  recovery, passkey-login rate limiting, admin isolation, device quotas, RBAC denial matrix, employee JML.
* **Frontend (Vitest)**: API client CSRF injection, permission gating helpers, form validation.
* **E2E (Playwright)**: passwordless bootstrap → passkey sign-in → create employee → RBAC denial as analyst.
* **Agent**: unit tests with mocked WMI/registry; integration on Windows VM with recorded evidence.
* **Security**: rate-limit tests, CSRF negative tests, header checks, dependency audit (`pip-audit`, `npm audit`).
