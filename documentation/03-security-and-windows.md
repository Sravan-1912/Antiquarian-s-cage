# Security Boundaries, Windows Requirements & Limitations

## 1. Trust boundaries

| # | Boundary | Untrusted side | Controls |
|---|---|---|---|
| B1 | Browser → Nginx | Internet / admin workstation | TLS 1.3, HSTS, CSP, rate limits |
| B2 | Nginx → API | Request content | Pydantic validation, session auth, CSRF, permission checks, ORM parameterisation |
| B3 | Agent → API | Endpoint (may be compromised) | mTLS, per-device cert, fingerprint re-check, payload size caps, schema validation, per-device rate limit, data stored as "reported" |
| B4 | API → Agent | Network & server compromise | Ed25519 command signatures with key separate from server TLS, expiry, nonce, allowlist on agent |
| B5 | Agent service → Broker service | Low-priv agent process | Named-pipe ACL, broker re-validates signature & schema, broker allowlist ⊆ agent allowlist |
| B6 | API → DB | App compromise | Least-privilege DB role, audit table INSERT-only, secrets in env/secret store |
| B7 | Admin → other admins | Insider | RBAC, audit chain with external HMAC key, sensitive actions require recent MFA |

## 2. Windows API / tooling requirements (Phase 2–4)

| Capability | Mechanism | Privilege |
|---|---|---|
| OS / hostname / build | `platform`, `winreg` (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion) | User |
| Manufacturer, model, serial | WMI `Win32_ComputerSystem`, `Win32_BIOS` | User |
| CPU / RAM | WMI `Win32_Processor`, `GlobalMemoryStatusEx` | User |
| Disks | `GetDiskFreeSpaceEx`, WMI `Win32_LogicalDisk` | User |
| Network | `GetAdaptersAddresses` (via `psutil`) | User |
| Firewall status | `HNetCfg.FwPolicy2` COM / `Get-NetFirewallProfile` | User (read) / **Admin** (set) |
| BitLocker | WMI `root\CIMV2\Security\MicrosoftVolumeEncryption` `Win32_EncryptableVolume` | **Admin** (read & write) |
| Defender | WMI `root\Microsoft\Windows\Defender` `MSFT_MpComputerStatus` | User (read) / **Admin** (prefs) |
| Secure Boot | `Confirm-SecureBootUEFI` / registry `SecureBoot\State` | **Admin** |
| Credential Guard | WMI `Win32_DeviceGuard` | User |
| SMBv1 | `Get-SmbServerConfiguration` | **Admin** |
| Guest account / local accounts | `NetUserGetInfo` / `Get-LocalUser` | User (read) / **Admin** (modify) |
| Password & lockout policy | `NetUserModalsGet` / `secedit /export` | **Admin** for secedit |
| Audit policy | `auditpol /get` | **Admin** |
| Screen lock | Registry `InactivityTimeoutSecs`, policy CSP | **Admin** to set |
| Windows Update | `Microsoft.Update.Session` COM search (`IsInstalled=0 and Type='Software'`) | User (slow) |
| USB storage events | WMI `Win32_VolumeChangeEvent` / `Win32_DeviceChangeEvent` subscriptions | User |
| USB storage restriction | Registry `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start`, Device Installation Restriction policies | **Admin** |
| Remote lock | `LockWorkStation` — must run **in the user's interactive session** (helper process) | User session |
| Restart | `InitiateSystemShutdownEx` | **Admin** (SeShutdownPrivilege) |
| Consent prompt / session indicator | Per-user tray helper launched via `WTSQueryUserToken`+`CreateProcessAsUser` from the broker | SYSTEM → user |
| Service install | `pywin32` `win32serviceutil` | **Admin** at install |

Features needing elevation are routed only through the broker (`CageBroker`), which exposes a fixed list
of operations; the collector agent runs as `NT AUTHORITY\LocalService`.

## 3. Technical limitations (stated honestly)

1. **Environment for this build**: the development machine currently has no PostgreSQL, Redis or Docker.
   Phase 1 code targets PostgreSQL; local verification needs one of them installed (see README).
2. **Windows features cannot be verified in CI** — they must be tested on a real or isolated Windows VM.
   Nothing in Phases 2–4 is marked working until that test is recorded in `documentation/test-log.md`.
3. **BitLocker enforcement** can trigger recovery-key prompts and requires TPM/policy prerequisites;
   the platform will *report* and *recommend* by default and enforce only for explicitly opted-in policies,
   escrowing the recovery key first.
4. **Windows Home editions** lack Group Policy, BitLocker management (device encryption only) and some
   Defender/Credential Guard features → checks return `NOT_APPLICABLE`/`UNKNOWN`, never PASS.
5. **Local password policy** applies only to local accounts; domain/Entra-joined devices are governed by
   the directory, so the platform reports effective state but does not fight domain GPO.
6. **Remote assistance**: building a full remote-desktop stack is out of scope initially. Phase 4 will
   broker consented sessions and integrate with Windows *Quick Assist*-style flows or an open protocol;
   no hidden capture is ever implemented.
7. **Endpoint-reported data can be forged** by a compromised endpoint. The compliance engine records it as
   evidence with provenance; it can raise confidence (e.g. TPM-backed health attestation) only in later work.
8. **Hash chaining** detects modification only when verified against an independently stored anchor/key;
   a privileged DB attacker can truncate the tail. Mitigation: periodic export of chain heads to an external
   write-once store (Phase 7).
9. **Email delivery** requires an SMTP relay; without it, verification/reset links are written to the server
   log only when `ENVIRONMENT=development` (never in production).
10. **OIDC/SAML integrations** are not claimed until an end-to-end login has been tested per application.
