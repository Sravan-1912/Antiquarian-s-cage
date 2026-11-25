# Cloud deployment guide (real HTTPS, friends' devices)

Goal: run Antiquarian's Cage on a public server over **HTTPS with your own domain**, so that passkeys work on any
device (your phone, a friend's laptop) and remote agents on friends' machines can enrol and be managed in real time.

This is the full Docker stack (`postgres` + `redis` + `api` + `web`/nginx). It does **not** depend on your PC staying
on. For the quick-and-temporary alternative, see the tunnel options in the chat; this guide is the permanent path.

> Running on your **own local Linux VM instead of a cloud VPS**? That works for the stack — see
> **Appendix A: Local VM + Cloudflare Tunnel** at the end. Read its caveat first: the tunnel covers the console and
> passkeys perfectly, but **not** the agent mTLS channel over the internet.

> **Why a domain + HTTPS is non-negotiable:** WebAuthn passkeys only work in a *secure context* — `https://` or
> `localhost`. The passkey is bound to the hostname (the "RP ID"), which comes from `PUBLIC_BASE_URL`. Plain HTTP or a
> raw IP will not work for sign-in.

---

## 0. What you must provide

| Need | Details |
|---|---|
| **A Linux server** | A VPS/cloud VM (e.g. Ubuntu 22.04+), public IP, 2 GB RAM is enough to start. Providers: Hetzner, DigitalOcean, Vultr, AWS Lightsail, Oracle Cloud free tier, etc. |
| **A domain name** | e.g. `cage.example.com`. A cheap domain is fine. You'll point it at the server's IP. |
| **Open ports** | Inbound **80**, **443** (console) and **8443** (agent channel) in the provider's firewall/security group. |
| **SSH access** | You run the deploy commands **on the server**, not on your PC. |
| **(Optional) SMTP** | For real invite/recovery emails (e.g. a transactional provider). Without it, use the break-glass CLI on the server to mint links. |

Everything below runs **on the server** over SSH unless noted.

---

## 1. DNS

Create an **A record**: `cage.example.com → <server public IP>`. Wait until `ping cage.example.com` resolves to your
server. This hostname is permanent — your passkeys bind to it, so don't change it later.

## 2. Install Docker on the server

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER      # log out/in so `docker` works without sudo
docker compose version             # confirm Compose v2 is present
```

## 3. Get the code onto the server

```bash
git clone <your repo URL> cage && cd cage
# or: scp/rsync this project to the server
```

## 4. Create the device CA + command-signing key (do this once, keep it safe)

These sign device certificates and agent commands. **Losing them invalidates every enrolled agent**, so back them up
offline.

```bash
DEVICE_CA_KEY_PASSPHRASE='<a long passphrase, 24+ chars>' \
  python3 infrastructure/scripts/create_device_ca.py ./pki "Your Org Name"
```

This writes `pki/device-ca.crt`, `pki/device-ca.key` (encrypted) and `pki/command-signing.key`. You'll:
- copy `pki/` into the `cagekeys` volume (step 7 handles this on first run), and
- copy `pki/device-ca.crt` to nginx so the `:8443` channel can verify agent client certs (step 6).

## 5. TLS certificates (Let's Encrypt)

nginx expects these files in `infrastructure/nginx/certs/`:

| File | What it is |
|---|---|
| `console.crt` / `console.key` | TLS cert+key for `cage.example.com` (port 443, the console) |
| `agent.crt` / `agent.key` | TLS cert+key for the agent channel (port 8443) — can be the **same** cert as the console |
| `device-ca.crt` | your device CA's public cert (from step 4) — used to verify agent client certificates |

Get a real cert with certbot (standalone, since nginx isn't up yet):

```bash
sudo apt-get install -y certbot
sudo certbot certonly --standalone -d cage.example.com
mkdir -p infrastructure/nginx/certs
sudo cp /etc/letsencrypt/live/cage.example.com/fullchain.pem infrastructure/nginx/certs/console.crt
sudo cp /etc/letsencrypt/live/cage.example.com/privkey.pem   infrastructure/nginx/certs/console.key
cp infrastructure/nginx/certs/console.crt infrastructure/nginx/certs/agent.crt
cp infrastructure/nginx/certs/console.key infrastructure/nginx/certs/agent.key
cp pki/device-ca.crt infrastructure/nginx/certs/device-ca.crt
```

(Let's Encrypt certs renew every ~90 days — set up `certbot renew` + re-copy, or use your provider's managed certs.)

## 6. Fill in `.env` (production)

```bash
cp .env.example .env
python3 infrastructure/scripts/generate_secrets.py >> .env   # DATA_ENCRYPTION_KEY, AUDIT_HMAC_KEY, POSTGRES_PASSWORD, APP_DB_PASSWORD
```

Then edit `.env` and set these for production (the app's startup guards **refuse to boot** if any are wrong):

```ini
ENVIRONMENT=production
PUBLIC_BASE_URL=https://cage.example.com
ALLOWED_ORIGINS=["https://cage.example.com"]
COOKIE_SECURE=true
TRUST_PROXY_HEADERS=true
AGENT_REQUIRE_MTLS=true
DEVICE_CA_KEY_PASSPHRASE=<the same 24+ char passphrase from step 4>
REDIS_PASSWORD=<generate one, e.g. `openssl rand -base64 24`>
# DATABASE_URL / MIGRATION_DATABASE_URL / REDIS_URL are overridden by docker-compose — leave as-is.
# SMTP_* : set to a real provider for invite/recovery emails, or leave blank and use break-glass.
SMTP_HOST=...
SMTP_PORT=587
SMTP_USERNAME=...
SMTP_PASSWORD=...
SMTP_FROM=no-reply@example.com
```

`generate_secrets.py` does **not** emit `REDIS_PASSWORD` or `DEVICE_CA_KEY_PASSPHRASE` — set those yourself. Never
commit `.env`.

## 7. Seed the CA volume and start the stack

```bash
# Put the CA/signing keys where the API expects them (the cagekeys volume → /app/var, CA dir is /app/var/pki)
docker compose up -d postgres
docker volume create antiquarians-cage_cagekeys
docker run --rm -v antiquarians-cage_cagekeys:/app/var -v "$PWD/pki":/src alpine \
  sh -c "mkdir -p /app/var/pki && cp /src/* /app/var/pki/"

docker compose up -d --build
```

The `migrate` service runs `alembic upgrade head` as the schema owner (validating the production config first); then
`api` starts as the least-privilege `cage_app` role, and `web` serves the console on 443 + the agent channel on 8443.

## 8. Harden the database and verify

```bash
docker compose exec -T postgres psql -U cage_owner -d antiquarians_cage < infrastructure/scripts/harden_db.sql
docker compose exec api python -m app.preflight          # must report 0 failed
```

## 9. Bootstrap the Super Admin

Open **https://cage.example.com/** in a browser → **Set up your organisation** → create the Super Admin **passkey**
(Windows Hello / phone / security key — all work now, because it's real HTTPS). Register a **second** passkey on
another device as backup.

> If email isn't configured and an admin is ever locked out, run break-glass on the server:
> `docker compose exec api python -m app.recover <email>` → it prints the `/recover` link.

## 10. Add friends' devices

### As console users (Admins)
Invite them (Administrators → Invite). They open the `/accept-invite` link **on their own device's browser** and create
a passkey — this now works because the site is HTTPS and the RP ID matches `cage.example.com`.

### As managed endpoints (agents on their laptops)
On each Windows laptop, install the agent (build it with `agent/installer/build.ps1`, or ship `dist/cage-agent.exe`),
then:

```powershell
# create an enrollment token in the console (Endpoints → Enrol an endpoint), then on the laptop:
cage-agent.exe enroll --server https://cage.example.com:8443 --token <TOKEN>
cage-agent.exe run        # or install as a service (see agent/README.md)
```

The agent reaches the mTLS channel on **:8443**, gets a device certificate, and from then on every request is
client-cert-verified. The device appears under **Endpoints** with live inventory, compliance and remote actions.

---

## Backups & security (do not skip)
- **Back up the `cagekeys` volume and `pki/` offline.** Losing the device CA / command-signing key means re-enrolling
  every agent.
- Back up the database (`infrastructure/scripts/cage_backup.py`) and the audit anchors.
- Keep `.env` secret; rotate secrets if the host is ever suspected compromised.
- Restrict SSH (keys only), keep the OS patched, and limit the provider firewall to 80/443/8443 (+ SSH).
- See `10-operations-runbook.md` for backup/restore drills and incident playbooks, and `SECURITY.md` for the model.

## Common gotchas
- **Passkey won't create / "not a secure context"** → the site must be `https://` with a valid cert, not the raw IP.
- **Changed the domain later** → passkeys are bound to the old hostname and stop working; you'd re-enrol via break-glass.
- **Agent can't connect** → provider firewall must allow **8443**, and `AGENT_REQUIRE_MTLS=true` requires the agent to
  have completed enrolment (it presents its device cert on later calls).
- **API refuses to start** → a production guard failed; `docker compose logs api` names the offending setting
  (`PUBLIC_BASE_URL` must be https, `COOKIE_SECURE`/`AGENT_REQUIRE_MTLS` must be true, passphrase length, etc.).

---

## Appendix A: Local VM + Cloudflare Tunnel (no VPS, no port-forwarding)

Run the Docker stack on your **own Linux VM** (VirtualBox/VMware/Hyper-V) and expose it to the internet over HTTPS with
a **Cloudflare Tunnel**. No public IP, no router config. Cloudflare provides the public TLS, which is exactly what
passkeys need.

### The one caveat (read first)
Cloudflare Tunnel proxies **HTTP(S)** and terminates TLS at Cloudflare's edge. It therefore **cannot carry the agent's
client-certificate (mTLS) handshake** on `:8443`. So:

| Part | Over Cloudflare Tunnel? |
|---|---|
| **Console + passkeys** (admins, your phone, friends anywhere) | ✅ Works fully |
| **Agents on friends' laptops, over the internet** | ❌ Not through the tunnel (mTLS can't pass). Options below. |

**Agent options with this setup:**
1. **LAN agents** — a friend's laptop on *your* network enrols against the VM's LAN IP on `:8443` directly (bring the
   device over, or same office Wi-Fi). Simplest, keeps the designed mTLS.
2. **Internet agents** — you need the real `:8443` reachable publicly, which means either a **public IP + router
   port-forward to the VM** (not possible behind CGNAT), or a **small VPS** (public IP, `:8443` works directly — use the
   main guide above). If managing *remote* friends' laptops is the priority, a cheap VPS is the clean fit.

> You *could* run with `ENVIRONMENT` not set to `production` to relax the `AGENT_REQUIRE_MTLS=true` guard and route
> `/agent/v1` through the tunnel without mTLS (requests are still individually signed by the device key). This is a
> weaker posture and not recommended for anything real — do it only for a throwaway demo.

### Prerequisites
- A Linux VM (Ubuntu 22.04+), 2 GB RAM, with Docker installed (main guide, step 2).
- A **domain added to Cloudflare** (free plan): sign up at cloudflare.com, add your domain, switch its nameservers to
  Cloudflare. (A free `*.trycloudflare.com` quick tunnel also works but its URL changes each restart, which breaks
  passkeys — use a domain for a stable hostname.)

### Steps (run on the VM)

1. **Bring up the stack** following the main guide (steps 3–8), with one change: you do **not** need Let's Encrypt
   certs, because Cloudflare provides the public TLS. Keep nginx's self-signed/dev certs for the internal hop —
   generate them with `python3 infrastructure/scripts/dev_tls.py` into `infrastructure/nginx/certs/` (console.crt/key,
   agent.crt/key), and still copy `pki/device-ca.crt` there. Set `.env` exactly as in step 6, with
   `PUBLIC_BASE_URL=https://cage.example.com` and `ALLOWED_ORIGINS=["https://cage.example.com"]`.

2. **Install cloudflared:**
   ```bash
   curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
   sudo dpkg -i cloudflared.deb
   cloudflared tunnel login          # opens a browser link; authorize your domain
   ```

3. **Create the tunnel and route the hostname:**
   ```bash
   cloudflared tunnel create cage
   cloudflared tunnel route dns cage cage.example.com
   ```

4. **Configure ingress** at `~/.cloudflared/config.yml` (point it at nginx's HTTPS, skipping internal cert check):
   ```yaml
   tunnel: cage
   credentials-file: /home/<you>/.cloudflared/<tunnel-id>.json
   ingress:
     - hostname: cage.example.com
       service: https://localhost:443
       originRequest:
         noTLSVerify: true
     - service: http_status:404
   ```

5. **Run it** (and install as a service so it survives reboots):
   ```bash
   cloudflared tunnel run cage          # test in the foreground first
   sudo cloudflared service install     # then run it as a managed service
   ```

6. **Open the console** at `https://cage.example.com/` → bootstrap the Super Admin passkey. It now works from any
   device, anywhere — because it's real HTTPS on a stable hostname.

### Result
- **Admins / passkeys:** friends anywhere open `https://cage.example.com`, accept an invite, create a passkey — done.
- **Endpoints:** enrol friends' laptops that can reach the VM on your LAN (`:8443`), or move to a VPS for remote agents.
