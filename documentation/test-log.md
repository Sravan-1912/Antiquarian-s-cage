# Verification log

Windows endpoint features are recorded here only after being exercised on a real or isolated Windows machine.

## 2026-11-06 — Phase 2, agent 0.2.0

**Machine:** ASUS Vivobook 16 (X1607CA), Intel Core Ultra 5 225H, 15.4 GB RAM, Windows 11 Home Single Language
build 26300.9711 (the developer's own workstation, not an isolated VM). Agent run interactively, **not elevated**,
key scope `user`. Backend: FastAPI on PostgreSQL 16.15, plain HTTP on localhost (`--allow-insecure-localhost`).

| Capability | Result | Notes |
|---|---|---|
| Enrollment with single-use token | ✅ | Token shown once in console; device certificate CN = server-assigned UUID |
| Double enrollment guard | ✅ | Agent refuses to enrol when a config already exists |
| Device key protection | ✅ | DPAPI blob; ACL limited to user, Administrators, SYSTEM (inheritance removed) |
| Signed heartbeat → "Online" | ✅ | Online only after first authenticated heartbeat |
| Inventory: OS, build, edition, hardware, serial, CPU, RAM, disks, NICs | ✅ | All populated from WMI/CIM + psutil without elevation |
| Firewall / Defender / Guest / SMBv1 / RDP / Credential Guard reporting | ✅ | Defender reported `disabled` (real-time protection off on this machine) |
| Secure Boot, BitLocker reporting | ⚠️ `unknown` | Require elevation; correctly reported as unknown, not compliant |
| Screen lock | ⚠️ `unknown` | No machine inactivity policy; per-user screen saver not yet evaluated |
| Suspend → agent notified on next heartbeat, inventory paused | ✅ | |
| Revoke credentials → next heartbeat rejected, agent backs off | ✅ | Immediate, no CRL needed |
| Re-enrol after revocation with new token | ✅ | New device record; revoked one kept for history |
| Dashboard / audit trail / notifications reflect the above | ✅ | Audit chain verified (18 records) |
| Windows service install (`installer/service.py`) | ❌ not verified | Needs an elevated prompt; not yet run |
| Running as `NT SERVICE\CageAgent`, machine-scope key | ❌ not verified | |
| mTLS through Nginx (`AGENT_REQUIRE_MTLS=true`) | ❌ not verified | Nginx/Docker not installed on this machine |
| Certificate auto-renewal | ✅ in tests only | Covered by backend + agent unit tests, not observed live (90-day certs) |
| Windows 10 / Pro / Enterprise / domain-joined devices | ❌ not verified | |

## 2026-11-06 — Phase 3, agent 0.3.0 / broker 0.3.0

Same machine (Windows 11 Home, build 26300). Agent and broker both run **unelevated** as the interactive user
(`cage-broker serve --dev-allow-current-user`), so the live test proves the full chain without changing the system.

| Capability | Result | Notes |
|---|---|---|
| Signed job delivery, agent validation, key pinning (first use) | ✅ | Agent pinned `cmd-…` key from the authenticated job channel |
| Broker refuses jobs before it is pinned | ✅ | Deployment → *needs attention: broker has no pinned command key* |
| Named pipe agent → broker, independent re-validation | ✅ | |
| Firewall policy on an already-compliant device | ✅ applied | Read real firewall state; "Already compliant", no change made |
| Screen-lock policy without elevation | ✅ needs attention | `Access is denied` → reported, registry verified unchanged |
| BitLocker policy without elevation | ✅ needs attention | BitLocker WMI requires admin; reported, never assumed |
| Unassign with rollback | ✅ applied | Broker restored its own recorded state (nothing to restore) |
| Compliance evaluation on real evidence | ✅ | 55 % non-compliant: Defender RTP FAIL, screen lock FAIL; BitLocker/Secure Boot/audit UNKNOWN; Credential Guard N/A (Home) |
| New collectors: update recency, account policy (NetUserModalsGet), USB storage, screen lock | ✅ | Audit policy → unknown without elevation |
| **Applying** changes as an elevated broker — other categories | ❌ not verified | Only screen lock was approved for a live test on this personal PC (see below) |
| Broker as `CageBroker` service, pipe restricted to `NT SERVICE\CageAgent` | ❌ not verified | |
| USB allowlist via Device Installation Restrictions | ❌ not verified | Pro/Enterprise feature; this machine is Home |
| Password complexity via secedit, Windows Update AU keys | ❌ not verified | |

### 2026-11-06 — Screen-lock policy, elevated broker (approved by the machine owner)

Broker started elevated via UAC (`cage-broker serve --dev-allow-current-user --exit-after-minutes 20`); agent unchanged
(unelevated). Registry checked independently with `Get-ItemProperty` at each step.

| Step | Result | Evidence |
|---|---|---|
| Baseline | — | `…\Policies\System\InactivityTimeoutSecs` absent; `HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel` absent |
| Retry deployment from console (signed job, broker re-validation) | ✅ applied | Detail: "Inactivity lock set to 600s with password on resume" |
| Registry after apply | ✅ | `InactivityTimeoutSecs=600`; `Control Panel\Desktop`: `ScreenSaveActive=1`, `ScreenSaverIsSecure=1`, `ScreenSaveTimeOut=600` |
| Compliance after next inventory | ✅ | `screen_lock` FAIL → PASS ("machine inactivity limit"); score 55 % → 64 %; still non-compliant (Defender RTP off) |
| Unassign → roll back (signed `policy.remove`) | ✅ applied | "Rolled back: previous configuration restored" |
| Registry after rollback | ✅ exact | Value removed; both keys created by the policy removed; pre-existing `System` key untouched |
| Compliance after rollback | ✅ | `screen_lock` PASS → FAIL; score back to 55 % |
| Audit trail | ✅ | `policy.deployment_created`, `policy.deployment_result`, `policy.unassigned`, rollback result |

Fix made during this test: rollback previously left empty registry keys that the policy had created; it now records
created keys (including missing parents) and removes them on rollback when empty (unit-tested on HKCU).

## 2026-11-06 — Phase 4, agent/broker 0.4.0

Same machine; agent unelevated; no broker running (the earlier elevated broker had exited).

| Capability | Result | Notes |
|---|---|---|
| Status inspection from console | ✅ | Uptime 9 d 4 h, CPU/memory, signed-in user, 315 processes, local accounts + Administrators |
| Assistance request with password re-entry | ✅ | Session `requested` → delivered on next poll |
| Consent prompt shown to the user, **Allow** clicked by the machine owner | ✅ | Recorded as granted by `VASAVI\CHITHIRALA VASAVI` |
| Red always-on-top indicator + Quick Assist launched | ✅ | Console showed session *active*, ends in 10 min |
| End session from console → indicator closed | ✅ | |
| End session from console → Quick Assist closed | ❌ **found bug** | Quick Assist runs at high integrity; unelevated `taskkill` → access denied, and the agent had reported success. Fixed: agent verifies closure, escalates the signed `assist.end` to the broker, reports *needs attention* if still open; server issues signed cleanup after endpoint-side end/expiry and raises a high-severity notification on incomplete cleanup (unit/integration tested) |
| Broker closing Quick Assist (elevated) | ❌ not verified live | Needs an elevated broker |
| Consent **decline** / timeout path | ✅ in tests only | |
| Remote lock / restart / account changes | ❌ not run live | Not run on the owner's PC without explicit agreement; covered by unit tests (incl. last-admin refusal) |
| Session 0 / service-mode UI launch | ❌ not implemented | Fails closed by design |

## 2026-11-06 — Phase 5 (identity security)

Console in the desktop app's built-in Chromium browser; PostgreSQL 16 dev database.

| Capability | Result | Notes |
|---|---|---|
| Invite employee to workspace (console button) → invitation email → activate | ✅ | Password policy correctly rejected a password containing the employee's name |
| Register OIDC application in console; secret shown once; status "not yet verified" | ✅ | |
| Assign application to employee | ✅ | |
| **Real SSO** from an independent relying party (`infrastructure/samples/oidc_sample_rp.py`) | ✅ | RP redirected to console sign-in ("to continue to Sample Wiki"); after password sign-in the RP verified state, PKCE, server-side code exchange, ID-token RS256 signature via JWKS, issuer/audience/expiry, nonce, userinfo |
| Application marked verified only after the real exchange | ✅ | Authentication events: `sso_authorize`, `sso_token` |
| Employee lands in "My workspace" with app tile; admin APIs refused | ✅ | |
| Passkey registration with Windows Hello in the built-in browser | ⚠️ partial | Windows Security "Save your passkey — iris@example.com, Passkey for localhost" prompt appeared (browser → Windows Hello path works); PIN not completed, prompt cancelled/timed out → app showed "Passkey prompt was cancelled or timed out", nothing stored. Full registration + sign-in not yet completed live |
| Passkey protocol (register, sign-in, wrong origin, no UV, replay, clone counter, revoke) | ✅ in tests only | Software authenticator verified by the real py_webauthn library |
| MFA-required app step-up, leaver revocation of SSO + passkeys | ✅ in tests only | |
| SAML | ❌ not implemented | |

## 2026-11-06 — Phase 6 (security operations)

| Capability | Result | Notes |
|---|---|---|
| Configuration alert from real endpoint data | ✅ | After agent inventory: "Antivirus real-time protection off on Vasavi" (high, configuration finding). Firewall on → no alert; BitLocker unknown → no alert |
| Alert email via durable outbox + scheduler | ✅ | `[HIGH] Antivirus real-time protection off on Vasavi` delivered to the dev mail outbox within one scheduler cycle |
| Reports CSV/PDF from live data | ✅ | endpoint_health, device_compliance, audit_history PDFs; security_alerts CSV; PDF layout inspected |
| Dashboard alert KPIs and charts | ✅ | |
| Failed-sign-in burst, password spray, success-after-failures, auto-resolve, agent silence, deployment failures, USB with policy, admin burst, remote anomalies, workflow + RBAC, preferences, outbox | ✅ in tests only | 10 backend tests |
| Celery beat (production scheduler) | ❌ not verified | Redis not installed |
| Real SMTP delivery | ❌ not verified | Development mail outbox only |

## 2026-11-06 — Phase 7 (hardening)

| Capability | Result | Notes |
|---|---|---|
| Dependency audit (pip-audit backend + agent, npm audit) | ✅ | No known vulnerabilities |
| Bandit static analysis | ✅ | Only accepted Low findings remain (see SECURITY.md); asserts replaced; absolute System32 paths |
| Secrets scan | ✅ | None committed; `.dockerignore` added |
| Audit anchoring — live | ✅ | Console *Anchor now* → record #63 anchored and written externally; *Verify integrity*: 63 records, 2 anchors (scheduler + manual), no problems |
| Audit anchoring — tamper scenarios | ✅ in tests | Tail truncation by an owner who disables the trigger (PostgreSQL), anchor deleted from DB, external file deleted, external write failure → alert, offline verifier rejects a forged line |
| Query scaling (N+1) on 310 seeded devices | ✅ | All 39 list/summary/report endpoints constant query count; 9 N+1s found and fixed |
| Playwright E2E (Edge) | ✅ 5/5 | Setup → email verification → sign-in; uniform wrong-password message; TOTP enrolment and MFA sign-in; create employee → audit → verify; invited Security Analyst: UI hides and API returns 403 for employee creation and admin invites |
| Backup → restore drill on the dev database | ✅ | 71 KB encrypted bundle; restored into a scratch DB; row counts match; audit chain (64) and anchors (2) verified with restored keys; scratch DB dropped |
| Backup tamper / wrong passphrase | ✅ | Both refused before anything is restored |
| Production guards | ✅ in tests | 11 tests; `app.preflight` on dev: 0 failed, 3 expected warnings (no Redis/SMTP/TLS locally) |
| Docker Compose stack, Nginx mTLS, Redis, SMTP | ❌ not verified | Not installed on this machine |

## 2026-11-06 — Phase 8 (phone sign-in) and Phase 9 (fleet overview, network usage)

| Capability | Result | Notes |
|---|---|---|
| Phone pairing / sign-in protocol | ✅ in tests | 9 backend tests with software EC and RSA keys: full flow, wrong number → denied + high alert, foreign-key signature, replay, other browser cannot collect, decoy for unknown email, expiry, pairing reuse/bad signature, removed phone |
| App protocol vs live dev API | ✅ | Node script reproducing `mobile/src/core.ts` byte-for-byte (Android-style wrapped Base64 RSA key): pair → browser phone sign-in → approve → session → removal rejected |
| Console: pairing QR, "Sign in with your phone" screen | ✅ | Rendered in the browser; QR single-use with countdown |
| Android release APK | ✅ built | `mobile/dist/cage-authenticator-1.0.0.apk` (85 MB, minSdk 24, target 36), signed with the project release key (apksigner verified, cert SHA-256 564a5289…); permissions limited to camera, internet, biometric, network state. Built on Windows from a mirrored path (`mobile/build-android.ps1`) because the apostrophe in the project path breaks React Native's cmd calls |
| App on a physical phone (camera scan, fingerprint, approval) | ❌ not verified | No phone connected to this machine |
| iOS .ipa | ❌ not built | Needs macOS or Expo EAS + Apple Developer account |
| Network usage from the real agent (0.5.0) | ✅ | After two heartbeats the dashboard showed 853 MB (849 MB received, 4.4 MB sent) for this PC while it downloaded Android build dependencies |
| Network counter logic | ✅ in tests | Deltas, reboot reset, baseline-only devices not counted, agent adapter filter keeps "Local Area Connection", skips loopback |
| Redesigned overview (health chip, KPI cards, platform, last contact, network) | ✅ | Live data: 1 urgent alert (Defender off), 1/1 device online, 3 active policies |

## 2026-11-07 — Phase 10 (Windows sign-in approved from the phone) — built, not yet on a lock screen

| Capability | Result | Notes |
|---|---|---|
| Server key escrow + approval flow | ✅ in tests | 6 tests (setup approval, single release, denial, cross-device, other SID, unassigned/no phone, revocation, key size); full suite 95/95 on PostgreSQL |
| Agent unlock relay | ✅ in tests | 4 tests incl. real named pipe in dev mode and refusal of a non-SYSTEM client in production mode (fails closed) |
| Credential provider core (C++) | ✅ | 28 checks: AES-GCM seal/open with wrong key / wrong SID / tamper rejection, machine DPAPI store, SID lookup, Kerberos packing, LSA lookup |
| Credential provider COM object outside LogonUI | ✅ | 16 checks via a harness that loads the DLL without registering it; no credential produced on any error path |
| DLL hardening | ✅ | /W4 /WX /sdl, Control Flow Guard, Spectre mitigations, ASLR, DEP (DLL characteristics 0x4160) |
| Registered on this PC's lock screen | ❌ deliberately not | Owner's personal PC; existing VirtualBox VM is Windows 7 (unsupported) — needs a Windows 10/11 test VM |
| Tile on a real lock screen, Windows accepting the credential | ❌ not verified | See documentation/12-windows-phone-unlock.md, verification plan |

### 2026-11-07 — Cage Authenticator 1.0.1 on a physical phone

| Step | Result | Notes |
|---|---|---|
| Install signed APK on vivo I2404 (Android) | ✅ | Sideloaded |
| Phone → PC network path | ⚠️ then ✅ | First attempt never reached the API (McAfee firewall active on the PC / Wi-Fi path); resolved by the owner, then `/authenticator/pair` arrived |
| Pairing: QR scan → fingerprint → signed proof of key possession | ✅ | Authenticator "vivo I2404", platform android, RS256 key from Android Keystore; app polling `/authenticator/pending` every 3 s |

## 2026-11-07 — Admin isolation (row-level multi-tenancy)

| Capability | Result | Notes |
|---|---|---|
| `owner_admin_id` on users/employees/devices/enrollment_tokens/endpoint_policies/security_alerts (migration 0011, up/down) | ✅ | Batch mode so it applies on SQLite and PostgreSQL |
| `tenant:global` permission attached to super_admin only | ✅ | RBAC sync verified in the dev DB |
| Two admins fully isolated; Super Admin sees all; admin creating stamps ownership | ✅ | 4 tests in test_admin_isolation.py (lists, get-by-id 404, dashboard counts, admin cannot create admins) |
| Super-admin-created analyst keeps org-wide view | ✅ | Org security staff are not tenant-scoped |
| Scoping applied to devices, employees, users, enrollment tokens, dashboard, alerts, compliance, policies, reports, network usage | ✅ | Central helper app/services/tenancy.py |
| Existing RBAC/secops tests updated for the new model | ✅ | Admin now manages only its own employees/alerts |
| Full suite | ✅ | 99 passed on PostgreSQL, 97 on SQLite (+2 skipped) |

## 2026-11-07 — Subscription tiers and device quotas

| Capability | Result | Notes |
|---|---|---|
| subscription_plans + subscriptions tables (migration 0012, up/down) | ✅ | Plan catalogue synced at startup: trial 5 / starter 25 / business 100 / enterprise 1000 / unlimited |
| Quota enforced at enrollment (agent channel, authoritative) | ✅ | 6th device on a trial admin rejected with HTTP 402; a pre-issued token is also rejected at enroll time |
| Friendly pre-check at enrollment-token creation | ✅ | 402 before issuing a token the agent could not use |
| Resolution: admin subscription → org default → built-in trial; Super Admin org-level uncapped | ✅ | test_subscriptions.py (6 tests) |
| Super Admin assigns a plan / org default; revoking a device frees a slot; admins cannot change plans | ✅ | PUT /admins/{id}/subscription, PUT /organization/subscription, GET /subscription(+/plans), GET /subscriptions |
| Full suite | ✅ | 105 passed on PostgreSQL, 103 on SQLite (+2 skipped) |
