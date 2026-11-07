# Security model

Full threat model and trust boundaries: `documentation/03-security-and-windows.md`.

## Implemented controls (Phase 1)

* **Passwords** — Argon2id (m=64 MiB, t=3, p=4), transparent rehash on login, policy: ≥12 chars, 3 of 4 classes,
  common-password and name/email checks. Timing equalised for unknown accounts.
* **Sessions** — 256-bit opaque tokens in `HttpOnly; SameSite=Strict; Secure` cookies; only SHA-256 hashes stored.
  Idle (30 min) and absolute (12 h) expiry; revoked on logout, password change/reset, role change, disable, suspension.
* **CSRF** — double-submit token (`cage_csrf` cookie ↔ `X-CSRF-Token` header, compared against a stored hash)
  plus Origin allow-list for state-changing requests.
* **MFA** — TOTP secrets encrypted with AES-256-GCM, bound to the user ID as associated data; time-step replay blocked;
  pending-MFA sessions cannot reach any API other than MFA verification and logout.
* **Brute force** — per-IP fixed-window limits (Redis in production, fail-closed), per-account lockout after 5 failures
  (also at the MFA step), uniform 401 for unknown user vs bad password.
* **Authorization** — permission strings resolved from DB-backed roles; every router declares its permission;
  tenant (organisation) scoping on every query; denials written to the audit log.
* **Input/output** — Pydantic validation (control characters rejected), ORM parameterisation, validation errors never
  echo submitted values, CSV export neutralises spreadsheet formulas, React escapes all rendered data.
* **Headers** — CSP, HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy, COOP; `Cache-Control: no-store` on API.
* **Secrets** — only from environment; startup fails without keys; production refuses insecure cookies, missing Redis/SMTP,
  or identical encryption/audit keys. Dev email goes to a local outbox, never to logs.
* **Database** — app role is not the schema owner; `audit_logs` UPDATE/DELETE/TRUNCATE blocked by trigger and grants.

## Audit hash chain — limitations

Each record stores `hash = SHA-256(prev_hash ‖ canonical(record))` and `mac = HMAC-SHA256(AUDIT_HMAC_KEY, hash)`.

* Detects modification, insertion or deletion **within** the chain. Without the HMAC key an attacker with DB write
  access cannot recompute a valid chain.
* Truncation of the newest records and wholesale re-chaining are detected by **anchors** (Phase 7): the chain head is
  signed with a dedicated Ed25519 key hourly and on demand, stored append-only in `audit_anchors` and appended to an
  external file (`AUDIT_ANCHOR_DIR`). Verification compares every anchor with the live chain; the scheduler re-checks
  the latest anchor every cycle and raises a critical alert. The external file is only as strong as its storage: put
  it on WORM/remote storage the API host cannot rewrite. A failed external write raises an alert (never silent).
  `infrastructure/scripts/verify_audit_anchors.py` verifies the file offline with the public key.
* An attacker who holds both DB write access **and** `AUDIT_HMAC_KEY` can forge history. Keep the key in a secret
  manager/HSM, separate from the database host and from `DATA_ENCRYPTION_KEY`; rotate with a documented re-anchor.
* SQLite (development only) has no trigger protection.

## Endpoint agent channel (Phase 2)

* Enrollment tokens: ~124-bit, single use, ≤24 h, stored as SHA-256, revocable; rate-limited endpoint.
* Device keys are generated on the endpoint (P-256) and never leave it; protected with DPAPI + restrictive ACL.
  The server ignores the CSR subject and issues CN=<device UUID>, clientAuth EKU, 90-day lifetime.
* Each agent request is signed over method, path, timestamp, nonce and body hash. The server rejects stale
  timestamps (±5 min), reused nonces (stored until expiry), unknown/revoked/unenrolled devices and expired certs.
* Production: Nginx `:8443` requires a client certificate chained to the device CA and forwards it; the API
  checks it is the device's *currently active* certificate (`AGENT_REQUIRE_MTLS=true`). Revocation is effective
  on the next request without CRL/OCSP distribution.
* Agent-reported data is stored as *reported*: strict schemas (unknown fields rejected, length/count caps,
  256 KB body cap); the source IP shown is the one observed by the server, not the one the agent claims.
* The collector is read-only, uses a fixed PowerShell allowlist and accepts no commands from the server.
* Device CA key: encrypted PEM (`DEVICE_CA_KEY_PASSPHRASE`). In development it is auto-created under `var/pki` with
  a passphrase derived from `DATA_ENCRYPTION_KEY`; production refuses to start without an explicitly created CA.
  Compromise of the CA key allows minting device certificates — but those devices would still need a DB record
  and matching active certificate to pass the API check.

## Signed commands and the privileged broker (Phase 3)

* Commands are Ed25519-signed envelopes with a separate signing key (not the device CA, not the audit key), 72 h
  expiry, single-use nonce and target device id. Only `policy.apply` / `policy.remove` exist; there is no
  shell/script execution path from the server.
* The unprivileged agent validates every envelope, then hands it to the broker, which **re-validates independently**
  with its own pinned key and replay store. A compromised agent therefore cannot make the broker do anything the
  server did not sign for that device.
* Rollback data lives only in the broker's SYSTEM-only directory; the broker ignores any state supplied with a request.
* Named pipe: local only (`PIPE_REJECT_REMOTE_CLIENTS`), DACL = SYSTEM, Administrators, `NT SERVICE\CageAgent`.
* Policy arguments reach PowerShell through environment variables populated from validated enums/integers, never by
  string interpolation of server data.
* Residual risk: whoever holds the command-signing key can push any *allowlisted* policy to any device. Keep it off
  the API host in production (HSM/KMS signer) — today it is a passphrase-encrypted file read by the API.
* Pinning: agents enrolled before Phase 3 pin the key on first use over the authenticated channel; key rotation needs
  re-provisioning until signed rotation is implemented.

## Remote administration (Phase 4)

* Only allowlisted actions exist (inspect, lock, restart/cancel, local account disable/enable/demote, assistance
  start/end). Each is signed, single-use, expires in 10–60 minutes and is schema-validated by server, agent and broker.
* Restart, account changes and assistance requests require the operator to re-enter their password; failures are
  audited (`remote.reauth_failed`). Every action carries a reason, signed into the job and recorded in the audit log.
* The broker refuses to disable or demote the last enabled local administrator.
* Remote assistance: consent by default (only a Super Admin can change it organisation-wide, audited), a permanent
  on-screen indicator, the user can always end the session, hard expiry on both sides, no hidden capture. Screen
  sharing is Windows Quick Assist; the broker's only effect for `assist.end` is closing it, and incomplete cleanup is
  surfaced as a high-severity notification rather than reported as success.
* IT Support can only act on endpoints assigned to them, and only start assistance if the organisation allows it.

## Identity and SSO (Phase 5)

* Passkeys via py_webauthn: user verification required, origin + RP ID bound, single-use 5-minute server-side
  challenges, sign-counter clone detection; only public keys are stored — no biometric data ever reaches the server.
* OIDC provider: authorization code + mandatory PKCE S256, exact redirect-URI match (unknown client/redirect errors
  are never redirected), hashed single-use 60-second codes, RS256 tokens with a dedicated signing key (separate from
  device CA, command and audit keys), hashed client secrets shown once, per-app MFA step-up based on RFC 8176 `amr`.
* Access is re-checked at authorize, token and userinfo; revoking an assignment or offboarding an employee takes
  effect immediately for userinfo. Issued ID tokens remain valid until expiry (5 minutes) — relying parties should keep
  their own sessions short or re-validate.
* The console's post-login redirect (`next`) only accepts this IdP's own `/api/v1/oidc/authorize?…` path.

## Known gaps (tracked for later phases)

* SAML, refresh tokens, RP-initiated logout and OIDC key rotation with overlapping key IDs.

* Signed command-key rotation; HSM/KMS-backed signing (Phase 7).
* User-session helper launch when the agent runs as a service (remote assistance currently fails closed there).
* Compliance evidence is endpoint-reported; no hardware-backed attestation yet.
* Agent binary signing and secure self-update — not implemented (build script notes signtool requirement).
* "Recent MFA" step-up for sensitive actions, PostgreSQL row-level security, key rotation tooling.
* Agent subprocesses use absolute System32 paths (GetSystemDirectoryW) to prevent binary planting (Phase 7 audit).
* Locked accounts return HTTP 423, which reveals that the account exists; accepted trade-off for operator clarity.

## Phase 7 security review (2026-11-06)

* Dependency audit: `pip-audit` (backend, agent) and `npm audit --omit=dev` — no known vulnerabilities.
* Bandit (backend, agent, broker): remaining findings are accepted — subprocess use in the agent (allowlisted tools,
  absolute paths, no shell), retry jitter using `random`, two false-positive "hardcoded password" strings.
  Security-relevant `assert`s were replaced with explicit checks (asserts vanish under `python -O`).
* Secrets scan: none committed; real values only in gitignored `backend/.env` and `backend/var/`. `.dockerignore`
  keeps `.env`, keys and local data out of image build contexts.
* Production guards refuse: insecure cookies, missing Redis/SMTP, short CA passphrase, mTLS off, non-https base URL or
  origins, SQLite, the API connecting as the schema owner, identical data/audit keys. `python -m app.preflight`
  checks the live deployment (role privileges, triggers, migrations, keys, anchor storage, Redis, SMTP).
* Backups are AES-256-GCM encrypted (scrypt-derived key), checksummed per member, and restore only into a new
  database; a wrong passphrase or a modified bundle is refused.

## Reporting

Report vulnerabilities privately to the platform owner; do not open public issues for security bugs.
