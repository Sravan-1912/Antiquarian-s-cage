# Remote administration

## Actions

| Action | Runs in | Needs | Behaviour |
|---|---|---|---|
| Status inspection | Agent (read-only) | `devices:remote`, reason | Uptime, CPU/memory, signed-in users, process count, disk free, local accounts, Administrators members |
| Lock | Agent in user session (`LockWorkStation`); broker in session 0 (`WTSDisconnectSession`) | reason | Immediate lock; unsaved work is kept |
| Restart | Broker | reason + **password re-entry** | `shutdown /r` with 60–3600 s on-screen warning and message; cancellable |
| Cancel restart | Broker | reason | `shutdown /a` |
| Disable / enable local account | Broker | reason + password | Refuses to disable the last enabled local administrator |
| Remove from Administrators | Broker | reason + password | Refuses to demote the last enabled local administrator |

All actions are Ed25519-signed, single-use, short-lived jobs (10–60 min) with a fixed parameter schema validated
three times (server, agent, broker). There is no arbitrary command or script execution path.

## Remote assistance

1. An operator with `devices:remote` (Admin, or IT Support for endpoints assigned to them if the organisation allows)
   requests a session with a reason and a maximum duration, confirming with their password. The endpoint must be online.
2. A signed `assist.start` job reaches the agent. **By default the person at the endpoint sees a consent prompt**
   (requester, reason, duration) that declines automatically after 2 minutes. Consent can only be disabled
   organisation-wide by a Super Admin (audited); the indicator is shown regardless.
3. On consent, a red always-on-top **"REMOTE ASSISTANCE ACTIVE"** banner with a countdown and an **End session**
   button stays on screen for the whole session, and Windows **Quick Assist** opens for the actual screen sharing
   (the helper and user exchange the Quick Assist code as usual).
4. The session ends when: the user clicks *End session*; the operator ends it in the console (signed `assist.end`);
   the endpoint's own timer or the server's expiry is reached; or the agent stops. Each path closes the banner and
   Quick Assist and is audited.
5. Quick Assist runs at high integrity, so the unprivileged agent cannot always close it. The agent then forwards
   the signed `assist.end` to the privileged broker, whose only effect for that command is closing `QuickAssist.exe`.
   When the session ended on the endpoint side, the server issues that signed cleanup job automatically. If cleanup
   still fails, the session is marked *cleanup incomplete* and operators get a high-severity notification — it is
   never reported as cleanly closed.

What is deliberately **not** implemented: hidden screen capture, keylogging, microphone access, silent sessions,
or any custom remote-control protocol.

## Limitations

* When the agent runs as a Windows service (session 0) it cannot show the consent prompt or banner; launching the
  helper into the user's session from the broker is not implemented, so requests fail closed ("needs attention").
* Commands are delivered on the agent's next poll (heartbeat interval, default 60 s).
* Quick Assist is Microsoft's tool: the platform controls *when* it may run and closes it, but does not see the
  session contents and cannot restrict what the helper does inside an approved session.
