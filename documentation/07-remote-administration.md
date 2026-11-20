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

## Remote desktop (RDP)

For full remote control, a Super Admin or assigned Admin can start an **unattended Remote Desktop** session from the
endpoint's page (**Remote desktop**). Unlike remote assistance it needs **no consent prompt and no password step-up** —
but it is *not* silent:

1. The console issues a signed `rdp.start` job (allowlisted, short-lived) carrying a one-time relay token. RBAC
   (`devices:remote`) and admin isolation still apply; the request is audited and notifies endpoint managers.
2. On the endpoint the agent **shows the mandatory banner first** ("● REMOTE DESKTOP ACTIVE", always-on-top, cannot be
   minimised, with an *End session* button). Only once the banner is on screen does the privileged broker enable native
   Windows Remote Desktop (`fDenyTSConnections=0`) and open the firewall. **If the banner cannot be shown, RDP is never
   enabled** — the session fails closed. There is no silent mode.
3. The agent then opens an **outbound WebSocket tunnel to the backend** (`/agent/v1/rdp/tunnel`) and bridges it to its
   local `127.0.0.1:3389`.
4. In the console, **Connect** mints a one-time operator token (`/remote-sessions/{id}/rdp-connect`) and the desktop app
   opens a matching outbound tunnel (`/api/v1/rdp/tunnel`), exposes a local port, and launches `mstsc` at it.
5. The backend **relay** copies bytes between the two tunnels (it never interprets RDP). Because **both ends dial out**,
   this works across any network — home Wi-Fi, mobile, another office — with **no VPN and no inbound firewall rule** on
   either side.
6. The session ends when: the person at the endpoint clicks *End session*; the operator ends it in the console (signed
   `rdp.end`); the timer/expiry is reached; or the agent stops. Every path closes the banner + both tunnels, has the
   broker **disable Remote Desktop and close the firewall again**, and is audited.

### Cross-network requirements

* The endpoints and the operator must reach the **same backend**. For devices on different networks that means a
  **publicly reachable (cloud) backend** (see `13-cloud-deployment.md`) — the agents dial out to it for heartbeats and
  for the RDP tunnel. The desktop app's default **loopback** backend is for a single local machine only.
* The admin uses the **installed desktop app** to connect (it provides the local tunnel + `mstsc`). Point it at the
  shared backend with `CAGE_REMOTE_BACKEND_URL=https://your-backend` instead of its bundled local one. A plain browser
  cannot open the local tunnel, so **Connect** there explains that the desktop app is required.
* The relay pairs the two tunnels **in one process**, so run a single backend instance (or sticky-route the two
  `/rdp/tunnel` paths of a session to the same instance).

### RDP limitations (not yet verified on real hardware)

* **Windows endpoints only** in this version; a Linux target returns "needs attention". The full path (enable → banner →
  tunnel → relay → `mstsc` → disable) has **not been verified on real machines across two networks** and must be tested
  on isolated VMs before relying on it — enabling RDP and editing the firewall are privileged, security-sensitive.
* Same session-0 caveat as assistance: if the agent cannot show the banner in the user's session, no RDP session starts.
* Between the banner closing and the server-issued `rdp.end`, there is a brief window before RDP is disabled (seconds),
  the same round-trip the assistance cleanup uses.

## Limitations

* When the agent runs as a Windows service (session 0) it cannot show the consent prompt or banner; launching the
  helper into the user's session from the broker is not implemented, so requests fail closed ("needs attention").
* Commands are delivered on the agent's next poll (heartbeat interval, default 60 s).
* Quick Assist is Microsoft's tool: the platform controls *when* it may run and closes it, but does not see the
  session contents and cannot restrict what the helper does inside an approved session.
