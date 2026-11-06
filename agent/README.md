# Antiquarian's Cage — Windows agent (0.2.0)

Separate from the backend. Python 3.13+, Windows 10/11.

```
cage_agent/
  core/         agent loop, configuration, identity (keys/CSR), communication (signed HTTPS, retries)
  collectors/   read-only inventory + security-state collection (fixed PowerShell allowlist, psutil, registry)
  security/     request signatures, DPAPI key storage + file ACLs
installer/      Windows service wrapper (pywin32), PyInstaller build script
tests/          unit tests + real collection on the local machine
```

Planned (Phase 3/4): `policies/`, `commands/` (allowlist, validator, executor) and a separate privileged **broker**
service. The collector never changes system configuration and accepts no commands from the server.

## Usage

```bash
python -m cage_agent collect                         # print what would be reported; no network
python -m cage_agent enroll --server https://agent.example.com --token XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
python -m cage_agent run                             # foreground loop (the service runs the same loop)
python -m cage_agent status
```

Development against a local HTTP backend requires `--allow-insecure-localhost` (only `localhost`/`127.0.0.1`
are accepted) and usually `--key-scope user --data-dir var/data` (no elevation needed).

### As a Windows service (elevated prompt)

```powershell
.\installer\build.ps1                                  # builds dist\cage-agent.exe and dist\cage-agent-service.exe
dist\cage-agent-service.exe --startup auto install
sc.exe config CageAgent obj= "NT SERVICE\CageAgent"   # virtual account, not LocalSystem
icacls "$env:ProgramData\AntiquariansCage" /grant "NT SERVICE\CageAgent:(OI)(CI)M"
dist\cage-agent.exe enroll --server https://... --token ... --service-account "NT SERVICE\CageAgent"
sc.exe start CageAgent
```

**Not yet verified** on a real machine — see `documentation/test-log.md`.

## Security properties

* Device key: ECDSA P-256 generated locally, protected with DPAPI, file ACL restricted; never transmitted.
* Every request is signed (`CAGE-AGENT-V1` canonical form: method, path, timestamp, nonce, body hash);
  the server rejects bad signatures, stale timestamps (±5 min) and replayed nonces.
* TLS verification is always on; plain HTTP is refused except explicit localhost development.
* Retries: exponential backoff with full jitter, bounded attempts; 401/403 are not retried (long back-off instead).
* Least privilege: runs without elevation; checks needing admin rights report `unknown`.
* Logs: rotating file at `<data-dir>\logs\agent.log` (2 MB × 5). No secrets are logged.
