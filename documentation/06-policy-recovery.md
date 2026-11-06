# Policy deployment, rollback and recovery procedures

## How a policy reaches an endpoint

1. An administrator creates or edits a policy. The server validates the configuration against a strict per-category
   schema (unknown fields rejected) and stores a new **version** + revision record.
2. Assigning endpoints creates one **deployment** and one **command job** per endpoint. The job is an Ed25519-signed
   envelope `{v, job_id, device_id, command, parameters, issued_at, expires_at, nonce, key_id}` valid for 72 h.
3. The agent pulls jobs over its authenticated channel (it never accepts inbound connections) and validates the
   envelope: allowlisted command, its own device id, pinned key id + signature, not expired, unseen nonce, policy
   version not older than the last applied, configuration valid under the agent's own copy of the constraints.
4. The agent forwards the envelope over a local named pipe to the **privileged broker**, which repeats the entire
   validation with its own pinned key and replay store, then runs the policy module.
5. The module reads the current state, changes only what is needed, and returns `previous_state`/`current_state`.
   The broker keeps the **original pre-policy state** in its own SYSTEM-only directory for rollback.
6. The result is reported and shown as: `pending` → `in_progress` → `applied` / `failed` / `needs_attention`;
   `offline` when the job expired before the endpoint fetched it; `revoked` after emergency revocation.

## No silent overwrites

* Nothing is changed when the endpoint already complies ("Already compliant").
* Every change is recorded with its prior value (deployment detail → expand row) and in the audit log.
* Report-only mode (`enforce: false`) is available for Firewall and Antivirus to observe before enforcing.
* One active policy per category per endpoint, so two policies never fight over the same setting.

## Rollback

*Unassign → "Unassign and roll back"* issues a signed `policy.remove` job. The broker restores **its own recorded**
state (never data supplied by the agent or server). Rolling back restores exactly what existed before the policy —
including insecure settings if that is what was there.

| Policy | What apply changes | What rollback restores | Manual recovery (elevated prompt) |
|---|---|---|---|
| Firewall | Enables selected profiles that were off | Turns off only profiles it turned on | `Set-NetFirewallProfile -Name Public -Enabled True/False` |
| BitLocker | Nothing (verification only) | Nothing | Supervised: escrow recovery key, then `manage-bde -on C:` |
| USB | `USBSTOR\Start`, `StorageDevicePolicies\WriteProtect`, or DeviceInstall restriction keys | Exact previous values / deletes values it created | `reg delete HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies /v WriteProtect /f`; `reg add HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR /v Start /t REG_DWORD /d 3 /f` |
| Antivirus | Re-enables real-time protection, updates signatures | Disables RTP only if it was off before *and* the policy turned it on | Windows Security → Virus & threat protection |
| Screen lock | `InactivityTimeoutSecs`, screen-saver policy values | Exact previous values / deletes created values | `reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /f` |
| Windows Update | AU policy keys (`NoAutoUpdate`, `AUOptions`, schedule) | Exact previous values | `reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /f` |
| Password | Local min length, lockout threshold/duration/window, complexity (secedit) | Previous values captured via NetUserModalsGet/secedit | `net accounts /minpwlen:0 /lockoutthreshold:10`; `secedit /configure` with a saved template |

If the broker's state directory is lost, automatic rollback is impossible; use the manual column, guided by the
"Previous state" recorded on the deployment in the console.

## Emergency command revocation

*Deployment → Revoke* (or `POST /command-jobs/{id}/revoke`): undelivered jobs are never handed out; delivered jobs are
listed as revoked on the agent's next poll and dropped if not yet executed. A job already executed cannot be revoked —
use rollback.

## Key management

* The command-signing key (`DEVICE_CA_DIR/command-signing.key`, Ed25519, passphrase-encrypted) is separate from the
  device CA and the audit HMAC key. Agents and brokers pin its key id; **rotation requires re-provisioning** pins
  (signed key-rotation messages are a Phase 7 item).
* Agents enrolled before Phase 3 pin the key on first use from the authenticated job channel (logged as a warning).
  Brokers are pinned explicitly by an administrator (`cage-broker pin`).
