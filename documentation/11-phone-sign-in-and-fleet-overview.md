# Phone approval sign-in (Phase 8) and fleet overview (Phase 9)

> **Removed in the passkey-only refactor (Phase 13).** Phone-approval *console* sign-in (`/auth/phone/start`,
> `/auth/phone/status`, "Sign in with your phone") no longer exists — the only console sign-in is a WebAuthn passkey
> (see `08-identity-and-sso.md`). A phone can still be a console passkey through standard WebAuthn (platform or
> cross-device/hybrid). **Phone-authenticator pairing is kept**, and the paired biometric key now drives **Windows
> laptop unlock only** (`12-windows-phone-unlock.md`). The section below is retained for historical context.

## Phone approval sign-in (historical)

```
Browser (console login)            API                                   Cage Authenticator (phone)
  email → "Sign in with your phone"
  POST /auth/phone/start  ───────▶ request {id, challenge, number 10-99},
                                   HttpOnly browser secret (this browser only)
  shows number "65"                                     ◀─── POST /authenticator/pending (poll secret)
                                                        ───▶ choices [65, 52, 75], IP, browser, org
                                                             user taps 65 → fingerprint/face prompt
                                                        ◀─── POST /authenticator/decide
                                                             signature over CAGE-APPROVE-V1|id|challenge|approve|65
                                   verify RS256/ES256 with paired key,
                                   number, expiry, single use
  POST /auth/phone/status ───────▶ approved → session cookies (amr: hwk, user, mfa, phone)
  → dashboard
```

| Threat | Control |
|---|---|
| Push/MFA fatigue (spamming approve prompts) | Number matching: the attacker's number is only on the attacker's screen; a wrong pick blocks the request and raises a **high** alert |
| Stolen phone | Approval needs a fresh biometric match: the signing key is bound to biometrics in the OS key store, no PIN fallback |
| Stolen poll secret | Only lists requests; cannot approve without the biometric key |
| Another browser collecting the session | The session is released only to the browser holding the request's HttpOnly secret |
| Account enumeration | Unknown / unpaired / disabled accounts get an indistinguishable decoy request that can never be approved |
| Replay | Challenge per request, single decision, single session collection, 2-minute expiry |
| Leaver / lost phone | Console *Remove* (user or admin with `users:manage`); offboarding removes all phones; the app forgets revoked accounts |

Pairing: Account → Security → *Pair a phone* shows a single-use QR (5 minutes) containing the server address and a
token; the app signs `CAGE-PAIR-V1|token|sha256(public key)` (biometric prompt), so a pairing proves key possession.

Files: `backend/app/services/phone_auth.py`, `backend/app/api/phone.py`, `frontend/src/pages/auth/PhoneSignIn.tsx`,
`frontend/src/modules/identity/PhoneCard.tsx`, app in `mobile/` (see `mobile/README.md`).

Limitations: no push notifications (app polls while open); Android face unlock is usually not accepted for
biometric-bound keys (fingerprint works); iOS build needs a Mac or Expo EAS with an Apple Developer account; not yet
tested on a physical phone. Windows sign-in from the phone is Phase 10 (`purpose = windows` is reserved in the model).

## Fleet overview and network usage

The dashboard opens with a health chip, three KPI cards and *Fleet analytics*. Every figure is computed from the
database:

| Figure | Source |
|---|---|
| Health chip | Green only with no open critical/high alerts and no non-compliant managed endpoints |
| Console users online | Users with a live session used in the last 15 minutes |
| Devices online / platform | Authenticated heartbeats within the offline threshold; OS family from inventory |
| Last contact time | Buckets of each device's last authenticated heartbeat |
| Policies active/inactive | Policy status |
| Network usage | Agent ≥ 0.5.0 sends cumulative bytes sent/received (all non-loopback adapters) with every heartbeat; usage = sum of increases between consecutive heartbeats in 24 h; a counter drop (reboot) restarts from zero; a device counts only after two readings (no "0 B" guesses). Per device: `GET /devices/{id}/network` |
