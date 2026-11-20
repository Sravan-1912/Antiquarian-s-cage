# 15 — Architecture & Flows (visual guide)

A diagram-first tour of **Antiquarian's Cage**: what the pieces are, how they talk, and how the main
journeys work end to end. The flow diagrams are [Mermaid](https://mermaid.js.org/) (GitHub renders them
inline); the relay animation is an SVG (open it directly for the full animation).

> New to the project? Start with [`00-complete-guide.md`](00-complete-guide.md) for prose, then come back here
> for the pictures. Security model: [`SECURITY.md`](../SECURITY.md). Remote admin: [`07-remote-administration.md`](07-remote-administration.md).

---

## 1. What it is, in one picture

Antiquarian's Cage is an **endpoint management + security platform**: a web console (also shippable as a
Windows desktop app), a FastAPI backend, and a cross-platform **agent** on each managed endpoint. Everything
an admin does to an endpoint travels as a **signed, allowlisted command**; anything privileged is executed by
a separate **broker** running as SYSTEM/root, so the network-facing agent stays least-privilege.

```mermaid
graph TD
  subgraph Operators
    C["Web console (SPA)"]
    D["Desktop app (Electron)<br/>launches mstsc for RDP"]
  end
  subgraph Backend["Backend (FastAPI + uvicorn)"]
    API["REST API /api/v1"]
    AG["Agent channel /agent/v1<br/>(signed requests, mTLS in prod)"]
    RELAY["RDP/assist relay<br/>(WebSocket byte bridge)"]
    SCH["Scheduler: alerts, anchors, email"]
    DB[("PostgreSQL / SQLite")]
    KV[("Redis — rate limiting")]
  end
  subgraph Endpoint["Managed endpoint"]
    AGENT["Agent (user session, least-privilege)<br/>inventory • banner • tunnel"]
    BROKER["Privileged broker (SYSTEM / root)<br/>RDP enable • restart • account changes"]
  end

  C -->|cookie session, RBAC| API
  D -->|same API| API
  API --> DB
  AG --> DB
  SCH --> DB
  API --> KV
  AGENT -->|signed heartbeat + inventory| AG
  AG -->|signed command jobs| AGENT
  AGENT <-->|named pipe, DACL-restricted| BROKER
  AGENT -.->|dial out| RELAY
  D -.->|dial out| RELAY
  RELAY -. bytes .-> AGENT
```

**Key idea:** the agent and broker are two **processes** with different privilege. The agent never holds admin
rights it doesn't need; it asks the broker (over a locked-down local pipe) to perform privileged actions, and
the broker refuses anything that isn't a correctly **signed, allowlisted** command for *this* device.

---

## 2. The cross-network relay (animated)

Remote Desktop and Remote Assistance work **across any network with no VPN and no inbound firewall hole**: the
endpoint and the operator *both dial out* to the backend, which pairs the two WebSocket tunnels and copies bytes
between them. The relay carries RDP straight to the endpoint's `127.0.0.1:3389`.

![Animated cross-network relay](assets/relay-flow.svg)

*(GitHub may show the SVG statically; open `documentation/assets/relay-flow.svg` in a browser to see the packets move.)*

---

## 3. Enrollment — how an endpoint joins

```mermaid
sequenceDiagram
  participant Admin as Admin (console)
  participant API as Backend
  participant Agent as Endpoint agent
  Admin->>API: Create enrollment token (label, validity or "Never")
  API-->>Admin: One-time token (shown once, stored hashed)
  Note over Agent: cage-agent enroll --server … --token …
  Agent->>Agent: Generate P-256 key (DPAPI/machine-id wrapped)
  Agent->>API: Enroll: token + CSR + hostname
  API->>API: Validate token (unused, not expired*), issue device cert (CN = device UUID)
  API-->>Agent: Device certificate + config
  Agent->>API: Signed heartbeat + inventory (timestamp, nonce, body hash)
  Note over Admin,API: Endpoint shows Online; inventory + compliance populate
```

\* **Indefinite tokens:** choosing *"Never (indefinite)"* stores a null `expires_at`, so the token never expires
(the expiry check is skipped). Handy so you don't "lose" the ability to (re)enroll an endpoint.

---

## 4. Sign-in & Super-Admin provisioning

Console sign-in is **password-based** (PBKDF2-HMAC-SHA256). Super Admins create organizations and admins; a new
admin is handed a **one-time temporary password** and is forced to reset it on first login.

```mermaid
sequenceDiagram
  participant SA as Super Admin
  participant API as Backend
  participant A as New Admin
  SA->>API: Create organization
  SA->>API: Create admin (for that org)
  API-->>SA: Temporary password (shown once) + must_change_password=true
  SA-->>A: Hand over temp password (out of band)
  A->>API: Login with temp password
  API-->>A: 200 + "must change password"
  A->>API: Set new password
  API-->>A: Session established (RBAC applies)
```

Break-glass recovery for a sole Super Admin: `python -m app.recover <email>`.

---

## 5. A privileged remote action (the signing chain)

Every remote action — restart, log off, disable account, remove-from-Administrators, RDP enable — is a **signed
command envelope**. Three independent layers validate it: the backend signs, the agent verifies + checks its own
allowlist, the broker re-verifies before doing anything privileged.

```mermaid
sequenceDiagram
  participant Op as Operator
  participant API as Backend
  participant Agent as Agent (user session)
  participant Broker as Broker (SYSTEM)
  Op->>API: Request action (e.g. device.restart)
  API->>API: Build envelope, sign (Ed25519), set expiry + nonce
  API-->>Agent: Deliver job (pull)
  Agent->>Agent: Verify signature, device, expiry, nonce, allowlist
  alt privileged action
    Agent->>Broker: Forward envelope over named pipe (DACL: SYSTEM/Admins/CageAgent)
    Broker->>Broker: Re-verify against pinned command key + allowlist
    Broker-->>Agent: Outcome (succeeded / failed / needs_attention)
  else unprivileged (e.g. inspect)
    Agent->>Agent: Execute locally
  end
  Agent-->>API: Report result (audited)
```

On **Linux** there is no separate broker process: the agent runs as a **root** systemd service and performs the
privileged action itself, with the same signed-envelope validation.

---

## 6. Remote Desktop session (end to end)

```mermaid
sequenceDiagram
  participant Op as Operator (desktop app)
  participant API as Backend relay
  participant Agent as Endpoint agent
  participant Broker as Broker (SYSTEM)
  Op->>API: rdp.start
  API-->>Agent: Signed rdp.start
  Agent->>Agent: Show on-screen banner FIRST (fail closed if none)
  Agent->>Broker: Enable RDP (reg + firewall)  [Windows]
  Broker->>Broker: Verify a listener comes up on :3389
  alt no RDP host (e.g. Windows Home)
    Broker-->>Agent: failed — "use Remote Assistance instead"
    Agent-->>API: needs_attention (banner torn down)
  else RDP host up
    Broker-->>Agent: succeeded
    Agent-)API: Dial out tunnel → wss://…/rdp/tunnel
    Op->>API: Connect → dial out tunnel (operator side)
    API->>API: Pair the two tunnels (stateless HMAC tokens)
    Op->>Agent: mstsc ↔ relay ↔ 127.0.0.1:3389
  end
```

* **Windows Home can't host RDP** (no RDP server) — the broker detects this and returns a clear message instead of
  a cryptic `mstsc` dialog. Use a **Pro/Enterprise** endpoint, or **Remote Assistance** below.
* **Linux** uses **xrdp** as the host; the agent enables it directly (no broker) and shows the banner in the
  logged-in desktop session; it fails closed if there is no graphical session.

---

## 7. Remote Assistance (works on Home)

```mermaid
sequenceDiagram
  participant Op as Operator
  participant API as Backend
  participant Agent as Endpoint agent
  Op->>API: assist.start
  API-->>Agent: Signed assist.start
  Agent->>Agent: Consent prompt (policy) → always-on-top "REMOTE ASSISTANCE ACTIVE" banner
  Agent->>Agent: Launch Windows Quick Assist (Get help)
  Note over Op,Agent: Operator runs Quick Assist "Help someone" → shares 6-digit code
  Op-->>Agent: Enter code → view / take control
  Note over Agent: End from either side → banner closed, Quick Assist killed (broker fallback), audited
```

---

## 8. Compliance evaluation

```mermaid
graph LR
  INV["Agent inventory<br/>(security evidence)"] --> EV["Compliance engine"]
  EV --> R{Per check}
  R -->|readable, good| P["PASS"]
  R -->|readable, bad| F["FAIL"]
  R -->|needs elevation / not reported| U["UNKNOWN<br/>(never compliant)"]
  R -->|feature absent on this host| NA["NOT_APPLICABLE<br/>(excluded from score)"]
  P --> S["Score = PASS / (enabled − N/A)"]
  NA --> S
```

* The agent reports security evidence; the engine turns it into PASS/FAIL/UNKNOWN/NOT_APPLICABLE.
* Elevation-gated checks (**Secure Boot, BitLocker, audit policy**) report **UNKNOWN** when the agent runs
  **unprivileged** — run the agent **elevated** (the auto-start task does) to resolve them.
* **BitLocker on Windows Home** is **NOT_APPLICABLE** (Home has no BitLocker) so it never drags the score down.
* Disable checks that don't apply to your fleet on the Compliance page.

---

## 9. Auto-start topology (Windows) & cloud deployment

How the agent + broker run unattended, and why the agent is a **logon task** (not a service):

```mermaid
graph TD
  subgraph Boot
    SVC["CageBroker — LocalSystem service (auto)<br/>pinned to this device's command key"]
  end
  subgraph Logon
    TASK["Agent — logon Scheduled Task<br/>Highest privileges, hidden, interactive session"]
  end
  TASK -->|"interactive session → banner can show"| BANNER["RDP / assist banner"]
  TASK -->|"token has Administrators → pipe admits it"| SVC
  note["A session-0 service can't show the mandatory banner,<br/>so the agent must run in the user session (elevated)."]
```

Cloud (Render free tier): one public web service runs the FastAPI backend serving the **console SPA + /api +
/agent + the relay WebSockets** on one HTTPS origin (no VPN; agents dial out). See
[`13-cloud-deployment.md`](13-cloud-deployment.md).

```mermaid
graph LR
  Browser["Console (browser or desktop app)"] -->|HTTPS| Web
  AgentA["Agent @ network A"] -->|dial out| Web
  AgentB["Agent @ network B"] -->|dial out| Web
  subgraph Render
    Web["cage-web (FastAPI, single instance)"] --> PG[("Postgres")]
    Web --> Redis[("Key Value")]
  end
```

---

## 10. Using it — the happy path

1. **Deploy the backend** (local, Docker, or cloud → [`13-cloud-deployment.md`](13-cloud-deployment.md)) and open the console.
2. **Bootstrap** the first Super Admin, then **create an organization** and an **admin** (hand over the temp password).
3. **Enrol an endpoint:** console → Endpoints → *Enrol an endpoint* (pick validity, or *Never*). Run the printed
   `cage-agent enroll …` on the endpoint.
4. **Install for auto-start** (optional, recommended): `agent/installer/install.ps1` (Windows) or
   `agent/installer/linux/install.sh` (Linux) → broker + agent start on every boot/logon.
5. **Manage it:** inventory, compliance, policies, remote actions, Remote Desktop (Pro/Linux) or Remote
   Assistance (any Windows), all audited.

| I want to… | Where |
|---|---|
| Understand the security model | [`SECURITY.md`](../SECURITY.md), [`03-security-and-windows.md`](03-security-and-windows.md) |
| Remote actions / RDP / assistance | [`07-remote-administration.md`](07-remote-administration.md) |
| Password auth & SSO | [`08-identity-and-sso.md`](08-identity-and-sso.md) |
| Deploy to the cloud | [`13-cloud-deployment.md`](13-cloud-deployment.md) |
| Ship the desktop app / auto-start | [`14-desktop-app.md`](14-desktop-app.md) |
| What's actually verified | [`test-log.md`](test-log.md) |
