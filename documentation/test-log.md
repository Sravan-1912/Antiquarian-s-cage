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
