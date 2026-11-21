# Identity, authentication and single sign-on

## Console sign-in: password

Console sign-in is **password-based** — PBKDF2-HMAC-SHA256 (stdlib, bundles cleanly into the frozen backend). Accounts
are **provisioned by a Super Admin**, not self-registered:

* **Bootstrap** — first-run `register` creates the first organization + Super Admin with a password.
* **Organizations** — a Super Admin creates organizations (`POST /organizations`).
* **Admins** — a Super Admin creates an admin for an organization; the backend returns a **one-time temporary password**
  (shown once in the console). The admin signs in with it and is **forced to reset it on first login**
  (`must_change_password` → `POST /auth/password`). This is the *handover*: credentials are created by the Super Admin
  and transferred to the admin, who immediately sets their own password.
* **Change password** — any user can change their own password; a failed login is **rate-limited** (per-IP and
  per-account, with lockout) and feeds the security-operations detection rules.
* **Break-glass** — `python -m app.recover <email>` is a server-only command (needs host DB access, like
  `app.preflight`) that recovers a sole Super Admin who is locked out.

WebAuthn **passkeys remain available** for sensitive-action **step-up** and as SSO/MFA authenticators (see *Passkeys*
below); they are no longer the sole sign-in. (The earlier passkey-only and phone-approval console sign-ins were removed.)

## Employee accounts (joiner / mover / leaver)

* *Employees → Invite to workspace* creates a sign-in account with the **Employee** role (`self:read` only) and emails
  a single-use invitation. Employees land in **My workspace**: their applications (launch tiles) and devices.
* **Suspend** disables the account and revokes sessions; **reactivate** re-enables it.
* **Offboard (leaver)** disables the account, revokes all sessions, **all application grants** and **all passkeys**
  in one transaction, and records counts in the lifecycle history and audit log.
* Employee accounts never appear among administrators and cannot reach admin APIs (enforced server-side).

## Passkeys (WebAuthn)

* Implemented with py_webauthn (server) and @simplewebauthn/browser (client); no custom crypto or protocol.
* Resident (discoverable) credentials, **user verification required** → a passkey sign-in counts as MFA
  (`amr: ["hwk"|"swk", "user", "mfa"]`).
* Challenges: 256-bit, server-side, single-use, 5-minute expiry. Origin and RP ID are checked, so a passkey cannot be
  used on a phishing site. Sign counters detect cloned authenticators. Users can name and remove passkeys;
  Super Admins can revoke any user's passkeys.
* Biometrics stay inside the authenticator (Windows Hello, Touch ID, phone, security key); the server stores only the
  public key, credential ID, counter and metadata.

## OpenID Connect provider

| Item | Value |
|---|---|
| Issuer | `PUBLIC_BASE_URL/api/v1/oidc` |
| Discovery | `<issuer>/.well-known/openid-configuration` |
| Flow | Authorization code + **PKCE S256 (mandatory)** |
| Client auth | `client_secret_basic` / `client_secret_post` (confidential), `none` (public, PKCE only) |
| Tokens | ID token RS256 (5 min, `kid` via JWKS), access token RS256 `at+jwt` (10 min) for userinfo |
| Scopes / claims | `openid profile email` → `sub, name, email, email_verified, employee_number, department, amr, auth_time, nonce` |

Controls: exact redirect-URI match (https, http only for localhost), errors for unknown clients/redirects are shown on
the IdP and never redirected, codes are hashed/single-use/60 s and bound to client + redirect + PKCE, the user must
hold an active assignment at authorize, token and userinfo time (revocation is immediate at userinfo), per-app
**MFA required** is satisfied by the passkey session (its `amr` already carries `mfa`), every
authorization and token exchange is an authentication event linked to the application.

**Integration status:** an application stays *configured — not yet verified* until a real authorization-code exchange
succeeds; changing its redirect URIs resets it to unverified.

## Not implemented

* SAML 2.0 (applications that only support SAML cannot be integrated yet).
* Refresh tokens, RP-initiated logout, dynamic client registration, consent screens (applications are admin-assigned).
* Signing-key rotation with overlapping `kid`s (Phase 7).
