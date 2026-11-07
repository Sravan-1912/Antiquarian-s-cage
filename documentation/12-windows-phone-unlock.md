# Windows sign-in approved from the phone (Phase 10)

**Status: built and tested off the lock screen; NOT yet installed on any lock screen.** It must be verified on a test VM
before it goes near a real PC (see "Verification plan").

## Components

| Component | Where | Runs as |
|---|---|---|
| Credential provider `CageCredentialProvider.dll` ("Sign in with your phone" tile) | `windows-cp/` (C++, MSVC) | Inside LogonUI.exe, SYSTEM |
| Unlock relay `\\.\pipe\AntiquariansCageUnlock` | `agent/cage_agent/unlock.py`, started by `cage-agent run` | Agent service |
| Escrow of the unlock key K | `backend/app/services/windows_unlock.py`, table `windows_unlock_keys` | API |
| Approval | Cage Authenticator (number match + fingerprint/face) | Phone |

## Flows

**One-time setup** (per Windows account per PC): the tile's *First time on this PC?* link → user name + current
Windows password → the provider checks the password with Windows (`LogonUserW`), creates a random 256-bit key **K**,
encrypts the password with AES-256-GCM (bound to the account SID), protects that blob with machine DPAPI and stores it in
`HKLM\SOFTWARE\AntiquariansCage\PhoneUnlock` (ACL: SYSTEM only). K goes through the relay to the server, which keeps it
*pending* until the device's assigned person approves "Set up phone sign-in for Windows on <PC>" on their phone. Then
Windows signs in with the typed password.

**Unlock / sign-in**: user name → → . The tile shows a number; the phone shows three numbers and asks for the fingerprint
or face. After a correct, signed approval the server releases K **once** to that device over its authenticated agent
channel; the relay passes it to the tile, which decrypts the password locally, hands it to Windows (Kerberos/Negotiate
interactive or workstation-unlock logon) and wipes it.

## Security properties

* **Split knowledge**: the PC holds only the encrypted password; the server holds only K. A stolen disk, a stolen
  database, or a stolen phone alone recovers nothing. K is released only to the enrolled device, for the enrolled SID,
  after a biometric-signed approval with the matching number.
* **Who approves**: the employee the endpoint is assigned to (their workspace account's paired phone). Unassigned
  endpoints, people without a workspace account or without a paired phone get a clear message on the tile.
* **Relay**: SYSTEM-only DACL (no Administrators), remote clients rejected, client token must be SYSTEM; the per-request
  secret never leaves the relay. Production mode never admits the interactive user (`--unlock-relay dev` exists for
  testing only).
* **Fails safe**: the tile only adds an option; the normal password/PIN tiles are untouched. Every failure is shown on the
  tile and logged to `%ProgramData%\AntiquariansCage\credential-provider.log` (never secrets). Not offered in UAC
  prompts, CredUI or change-password.
* **Password changes**: if Windows rejects the stored password, the tile deletes its blob and asks for a password
  sign-in and a fresh setup.
* **Revocation**: console endpoint page or Account → (API `/me/windows-unlock`), offboarding removes all setups; a
  revoked setup cannot release K any more. Denials raise the *Sign-in approval refused* alert.
* Binary: `/W4 /WX /sdl`, Control Flow Guard, Spectre mitigations, ASLR/DEP; secrets in self-wiping buffers.

## What is verified (2026-11-07)

| Check | Result |
|---|---|
| Server escrow (6 tests): setup needs approval, unlock releases K once, denial/wrong number releases nothing, another device cannot read the request, another SID is not enrolled, unassigned/no-phone explained, revoked setup cannot unlock, K must be 32 bytes | ✅ |
| Relay (4 tests): secret never leaves the relay, single use, server errors explained, real named pipe round trip (dev mode), non-SYSTEM client refused in production mode | ✅ |
| Provider core (28 checks): JSON, base64, AES-GCM seal/open incl. wrong key / wrong SID / tampering, machine-DPAPI store, SID lookup, Kerberos packing layout, LSA Negotiate lookup, relay-down reporting | ✅ |
| Provider COM object loaded outside LogonUI (16 checks): scenarios offered/refused, fields, no auto-logon before approval, error paths produce no credential | ✅ |
| **Tile on a real lock screen, setup, phone approval, Windows accepting the credential, password-change handling** | ❌ not yet — needs the test VM |

## Verification plan (test VM)

1. Windows 10/11 VM (VirtualBox or VMware is installed on the host), snapshot **before** step 3.
2. In the VM: Python 3.13+, `agent/` installed, enrolled against the host API (`http://10.0.2.2:8000` from VirtualBox
   NAT), running as a service; assign the endpoint to an employee with a paired phone.
3. Copy `windows-cp/out/CageCredentialProvider.dll` + `install.ps1`; run elevated.
4. Win+L → *Sign-in options* → phone tile → *First time on this PC?* → setup → approve on the phone → signed in.
5. Lock again → phone tile → approve → unlocked. Then: deny, wrong number, timeout, agent stopped, network cable
   unplugged, password changed elsewhere, endpoint unassigned, setup revoked in console — each must show a clear
   message and leave the password tile working.
6. `uninstall.ps1 -RemoveSavedPasswords`; confirm the tile is gone.
