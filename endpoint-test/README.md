# Antiquarian's Cage — laptop test, install to uninstall

Roles: **PC** = your computer running the server (192.168.0.100). **Laptop** = your friend's laptop. **Phone** = your
phone with Cage Authenticator.

## Part 0 — Before you start (with your friend)
1. Get your friend's OK. Tell them the agent reports hardware, IP addresses and security settings to your server, and
   that everything is removed at the end.
2. Laptop: Windows 10 (2004+) or 11, administrator access, connected to **the same Wi-Fi as the PC**.
3. Laptop: create a restore point — Start → "Create a restore point" → *Create* → name "before Cage test".
4. Laptop (recommended): create a separate local test account — Settings → Accounts → Other users → *Add account* →
   "I don't have this person's sign-in information" → "Add a user without a Microsoft account" → name `cagetest`, a
   throwaway password. All lock-screen tests use this account, never your friend's own.
5. Laptop: check **Smart App Control** — Windows Security → App & browser control → Smart App Control settings.
   * **Off** (or not present on Windows 10): the lock-screen tile can be tested.
   * **On / Evaluation**: only the agent part can be tested; the tile will be skipped (Windows blocks unsigned
     sign-in components). Do **not** turn it off on a friend's laptop — on many builds it cannot be turned back on
     without resetting Windows. Use the VM for the tile instead.

## Part 1 — Prepare the PC (server side)
1. McAfee firewall on the PC: allow **TCP 8443** for home networks (same screen as port 8000 before).
2. Make sure the servers are running (Claude starts them: API on 8000 for the phone, HTTPS on 8443 for agents, console
   on 5173).
3. Console → **Endpoints** → *Enrol endpoint* ("Enrol an endpoint" dialog): label "Friend laptop test", assign to
   employee **Iris Calloway**, validity 60 minutes → **Generate token** → copy the token (shown once).
4. Pair your phone to Iris as well (she approves the laptop's sign-ins): in a private browser window open
   http://localhost:5173, sign in as `iris@example.com` (password in `backend/var/dev-credentials.txt`) → Account
   security → *Pair a phone* → in Cage Authenticator tap **Pair another account** → scan → fingerprint.

## Part 2 — Install on the laptop
1. Install **Python 3.14** from https://www.python.org/downloads/ → run the installer → tick **"Add python.exe to PATH"**
   → *Customize installation* → *Next* → tick **"Install Python for all users"** → *Install*.
2. Copy `cage-endpoint-test.zip` to the laptop (USB / Drive) and extract it, e.g. to `C:\CageTest`.
3. Start → type PowerShell → right-click *Windows PowerShell* → **Run as administrator** → then:
   ```powershell
   cd C:\CageTest
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\Install-CageEndpoint.ps1 -Token PASTE-TOKEN-HERE -Server https://192.168.0.100:8443 -WithTile
   ```
4. Watch for green **Done**. Every step prints its result; a red **STOPPED** line says exactly what to fix.
5. PC → console → **Endpoints**: the laptop appears **Online**, assigned to Iris; open it to see hardware, security
   state, compliance and (after two minutes) network usage.

## Part 3 — Test the agent (works with Smart App Control on)
| Test | Do | Expect |
|---|---|---|
| Inventory | Open the endpoint page | OS, model, CPU, disks, NICs, firewall/antivirus/BitLocker state |
| Heartbeat | Wait 3 min | "Last heartbeat" keeps updating |
| Offline | Turn off the laptop's Wi-Fi for 5 min | Endpoint turns **Offline**; after 15 min an "agent stopped reporting" alert |
| Back online | Turn Wi-Fi on | Online again, alert auto-resolves |
| Remote inspect | Endpoint → Remote administration → *Inspect* | Uptime, signed-in user, processes |
| Suspend / reactivate | Endpoint → Suspend, then Reactivate | Agent reports only heartbeats while suspended |

## Part 4 — Test the lock screen (only if Smart App Control is Off and the tile was installed)
1. Laptop: sign out, or press Win+L.
2. Click **Sign-in options** → choose the phone tile **"Sign in with your phone"**.
3. **First-time setup**: click *First time on this PC? Set up phone sign-in* → user name `cagetest` → password →
   press **→**. The tile shows a number.
4. Phone (app open): "Set up phone sign-in for Windows on <laptop>" → tap the same number → fingerprint.
   The laptop signs in to `cagetest`.
5. **Unlock without password**: Win+L → phone tile → user name `cagetest` → **→** → number appears → phone: tap the
   number → fingerprint → laptop unlocks.
6. Safety checks (each from step 5): tap the **wrong number** (blocked + alert on PC), **Deny** (blocked), **do nothing
   2 min** (expired message), **turn off Wi-Fi** first (tile says the server can't be reached — password tile still
   works), **remove the setup** in the console endpoint page (tile says it is not set up).
7. Password tile check: at any point the normal password/PIN sign-in must still work.

## Part 5 — Uninstall (leave nothing behind)
1. Laptop: sign in with **your friend's normal account** (password/PIN).
2. Elevated PowerShell:
   ```powershell
   cd C:\CageTest
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\Uninstall-CageEndpoint.ps1
   ```
   Expect green "removed". If it reports a locked file, restart the laptop and run it again.
3. PC → console → the endpoint → **Unenroll** (its certificate stops working).
4. Laptop: delete the `cagetest` account (Settings → Accounts → Other users → Remove), delete `C:\CageTest`, and
   uninstall Python (Settings → Apps) if it was only for this test.
5. PC: remove the McAfee port rules for 8000/8443 when you no longer need them.

## If something goes wrong
* Lock screen misbehaves: use the normal password/PIN tile (it is never removed), then run the uninstaller.
* Cannot sign in at all (should not happen): restart → hold Shift while clicking Restart → Troubleshoot → System
  Restore → "before Cage test".
* Logs: laptop `C:\ProgramData\AntiquariansCage\logs` (agent) and
  `C:\ProgramData\AntiquariansCage\credential-provider.log` (tile).
