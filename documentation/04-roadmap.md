# Development Roadmap, Risks & Testing

## Phases

| Phase | Scope | Exit criteria |
|---|---|---|
| 1 Foundation | Repo, design system, admin auth (register-first-admin, login, logout, reset, verify, TOTP MFA, sessions, lockout), RBAC, audit chain, dashboard (real queries), employees + JML | Backend + frontend run against PostgreSQL; pytest green; registration/login/RBAC verified manually |
| 2 Endpoint mgmt | Agent skeleton, enrollment tokens, device CA, mTLS, heartbeat, inventory, lifecycle ops | Agent enrolled on a Windows VM; heartbeat/offline transitions observed; cert revocation blocks agent |
| 3 Security mgmt | Policy engine, 7 policy categories, signed jobs, broker service, compliance engine (12 checks) | Each policy applied & rolled back on a VM; UNKNOWN never counted compliant |
| 4 Remote admin | Lock, restart, consented assistance sessions, session expiry | Consent prompt + indicator verified; denial path verified |
| 5 Identity security | Employee login, WebAuthn passkeys, OIDC provider, app assignments | Passkey round trip in Chrome/Edge; OIDC login tested against a sample relying party |
| 6 SecOps | Alert rules, alert workflow, notifications (in-app/email/WS), reports CSV/PDF | Each detection triggered by a reproducible scenario |
| 7 Hardening | DB roles/RLS, audit anchor export, load tests, backup/restore drill, threat-model review, pentest checklist | Documented results |

## Status (2026-11-06)

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
  SAML not implemented.
* **Phase 6 — implemented**; alert detection, email outbox delivery and reports verified live on real endpoint data.
  The agent-silence alert and the heartbeat-retention purge (previously deferred) now run in the scheduler.
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
| Insider admin abuse | Data/device misuse | RBAC, audit chain with external key, recent-MFA for sensitive ops |
| Python agent footprint | Performance, AV false positives | PyInstaller signed builds; consider Rust/Go rewrite of broker later |

## Testing requirements

* **Backend (pytest)**: unit tests for password policy, hashing, TOTP, CSRF, permission resolution, audit chain verification; API tests for auth flows, lockout, RBAC denial matrix, employee JML.
* **Frontend (Vitest)**: API client CSRF injection, permission gating helpers, form validation.
* **E2E (Playwright)**: register → login → MFA enrol → create employee → RBAC denial as analyst.
* **Agent**: unit tests with mocked WMI/registry; integration on Windows VM with recorded evidence.
* **Security**: rate-limit tests, CSRF negative tests, header checks, dependency audit (`pip-audit`, `npm audit`).
