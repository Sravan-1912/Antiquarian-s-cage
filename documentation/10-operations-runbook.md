# Operations runbook

Day-to-day operation, deployment, backup/restore and incident procedures. Commands assume the repository root.
Windows paths are shown for the development machine; the Docker stack uses the same commands inside containers.

## 1. First deployment

1. **Secrets** — `python infrastructure/scripts/generate_secrets.py` → put the values into the secret manager /
   `.env` (never commit). Set `ENVIRONMENT=production`, `PUBLIC_BASE_URL=https://…`, `ALLOWED_ORIGINS=["https://…"]`,
   `SMTP_*`, `REDIS_URL`, `DEVICE_CA_KEY_PASSPHRASE` (≥ 24 chars), `AGENT_REQUIRE_MTLS=true`.
2. **Offline keys** — on an offline machine:
   `DEVICE_CA_KEY_PASSPHRASE=… python infrastructure/scripts/create_device_ca.py ./pki "Org name"`
   creates `device-ca.{crt,key}` and `command-signing.key` (both keys encrypted). Copy `pki/` into the `cagekeys`
   volume (`/app/var/pki`) and `device-ca.crt` to Nginx (`ssl_client_certificate`). Keep an offline copy.
3. **TLS** — console certificate/key at `infrastructure/nginx/certs/console.{crt,key}`.
4. **Start** — `docker compose up -d --build`. The `migrate` service runs `alembic upgrade head` as `cage_owner` with
   the full production configuration (the guards validate it first); the API then runs as `cage_app`.
5. **Harden** — `docker compose exec postgres psql -U cage_owner -d antiquarians_cage -f - < infrastructure/scripts/harden_db.sql`
6. **Preflight** — `docker compose exec api python -m app.preflight` must report `0 failed`. Paste the output into the
   change record.
7. **Bootstrap** — open the console; the first visit creates the organisation and Super Admin and runs the passkey
   registration ceremony (no password is ever set). **Register a second passkey immediately** (a different device or a
   security key) so a single lost/broken authenticator cannot lock out the sole Super Admin.
8. **Anchor storage** — mount WORM / remote storage at `/app/anchors` (`cageanchors` volume by default). Check the
   audit page shows "written to external anchor storage" after the first hour (or press *Anchor now*).

> Not verified in this repository's environment: the Docker stack (Docker is not installed on the development
> machine), Nginx mTLS, Redis and real SMTP. Run steps 4–6 on a staging host before production.

## 2. Routine checks

| When | What | Where |
|---|---|---|
| Daily | Open critical/high alerts, especially `Audit log integrity check failed` and `Audit anchor not written externally` | Alerts |
| Daily | Agents silent / deployments needing attention | Alerts, Endpoints |
| Weekly | *Verify integrity* on the audit page (chain + anchors) | Audit log |
| Weekly | Copy the external anchor file to a second location; run `verify_audit_anchors.py` against it | ops host |
| Monthly | Restore drill (below) | ops host |
| After every deploy | `python -m app.preflight` | API container |
| Quarterly | `pip-audit`, `npm audit --omit=dev`, Bandit, dependency upgrades | CI / dev |

## 3. Backup

`infrastructure/scripts/cage_backup.py` produces one encrypted bundle: database dump (`pg_dump -Fc`), the key directory
(device CA, command-signing, OIDC, audit-anchor keys) and the anchor files, with a SHA-256 manifest and row counts.

```bash
export MIGRATION_DATABASE_URL=postgresql+psycopg://cage_owner:…@host:5432/antiquarians_cage
export BACKUP_PASSPHRASE=…        # from the secret manager, >= 16 chars
python infrastructure/scripts/cage_backup.py backup --out /backups
```

* Schedule at least daily; keep ≥ 30 days; copy off-host.
* The bundle does **not** contain `DATA_ENCRYPTION_KEY` / `AUDIT_HMAC_KEY`. Without them a restored database cannot
  decrypt MFA secrets or verify the audit chain — back them up in the secret manager, separately.
* Press *Anchor now* before planned maintenance so the backup ends on an anchored head.

## 4. Restore

```bash
export RESTORE_ADMIN_URL=postgresql://postgres:…@host:5432/postgres   # only to CREATE the target database
python infrastructure/scripts/cage_backup.py restore --bundle cage-….cagebak --target-db antiquarians_cage_restored --keys-dir /restore/pki
```

The tool refuses to restore into an existing database or over a non-empty key directory, refuses a bundle that fails
decryption or checksum, and compares row counts with the manifest. Then: point `DATABASE_URL`/`MIGRATION_DATABASE_URL`
at the restored database, copy `/restore/pki` into the key volume, start the API, run `python -m app.preflight`, and
press *Verify integrity*. Anchors newer than the backup will be reported as "anchored but no longer exists" — that is
expected after a restore to an older point; record it in the incident and anchor the restored head.

### Restore drill (monthly)

```bash
python infrastructure/scripts/cage_backup.py drill --out /backups
```

Backs up, restores into a throwaway database, verifies the audit chain **and** anchors with the application code using
the restored keys, then drops the throwaway database. Last run: see `test-log.md`.

## 5. Incident procedures

**Audit integrity alert (critical).** Do not anchor or "fix" anything. Preserve evidence: take a backup bundle, copy
the external anchor file, export the audit CSV. Compare the last external anchor (`verify_audit_anchors.py`) with the
database. Review PostgreSQL logs for `ALTER TABLE … DISABLE TRIGGER`, superuser logins and connections as `cage_owner`.
Rotate `AUDIT_HMAC_KEY` and database passwords if the database host is suspected compromised.

**Anchor external write failed (high).** Check the mount/permissions of `AUDIT_ANCHOR_DIR`; the alert auto-resolves on
the next successful write. Until then truncation is only detectable from the database copy.

**Lost command-signing key / device CA.** Restore `pki/` from the latest bundle. If unrecoverable: create new keys,
every agent must re-pin (signing key) or re-enrol (CA). This is why the keys are in every backup.

**Admin locked out of their passkey (normal recovery).** Another administrator with `users:manage` opens
Administrators → the user → **Send recovery link** (or `POST /users/{id}/recovery`). The emailed `/recover` link runs a
passkey registration ceremony that revokes the user's old passkeys and enrols a new one. Audited.

**Sole Super Admin lost every passkey (break-glass).** With host/DB access, run
`docker compose exec api python -m app.recover <email>`. It mints a single-use `passkey_recovery` token and prints the
absolute `/recover` enrolment URL; open it to register a fresh passkey and sign back in. This command is the reason
admin-issued-only recovery is safe — guard host access accordingly, and afterwards register a second passkey.

**Suspected compromised admin account.** Administrators → disable account (revokes sessions) → review the audit log
filtered by that actor → revoke their passkeys → check alerts for `admin_activity_burst`.

**Agent fleet stops reporting.** Check the API health (`/api/v1/health`), Nginx 8443 listener and its client CA, and
certificate expiry on the device page. Agents back off and resume automatically.

## 6. Performance baseline (2026-11-06, PostgreSQL 16, development laptop)

`backend/tests/test_performance.py` seeds 310 devices (inventory, 12 compliance results each, heartbeats, alerts,
employees) and calls every list/summary/report endpoint. All use a constant number of SQL statements regardless of
fleet size. Slowest at 310 devices: employee-access report 242 ms, compliance-report 102 ms, endpoint-inventory
report 84 ms; every other endpoint < 40 ms. Fixed in Phase 7: compliance summary was 627 queries / 216 ms →
9 queries / 23 ms; device-compliance report 629 queries / 698 ms → 11 / 102 ms.

## 7. API reference

`documentation/api/openapi.json` (OpenAPI 3, 115 paths / 132 operations, exported 2026-11-06). In development the
interactive docs are at `/api/docs`; they are disabled in production. Regenerate with:

```bash
cd backend && python -c "import json; from app.main import create_app; print(json.dumps(create_app().openapi(), indent=2))" > ../documentation/api/openapi.json
```
