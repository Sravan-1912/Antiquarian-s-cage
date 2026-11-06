# Database Schema

PostgreSQL 16. All externally exposed identifiers are UUID v4 (`id uuid primary key`).
All tables have `created_at timestamptz not null default now()`; mutable tables also have
`updated_at`. Tenant-scoped tables carry `organization_id uuid not null references organizations(id)`.

Legend: **[P1]** implemented in Phase 1 migration, others are designed and land in their phase.

## Identity & access

| Table | Key columns | Constraints / indexes |
|---|---|---|
| organizations **[P1]** | name, slug, settings jsonb | unique(slug) |
| users **[P1]** | organization_id, email, full_name, password_hash, status(active/locked/disabled/pending), email_verified_at, mfa_secret_enc (AES-GCM), mfa_enabled, failed_login_count, locked_until, last_login_at, password_changed_at | unique(organization_id, lower(email)) |
| roles **[P1]** | organization_id NULL (=system role), key, name, description | unique(organization_id, key) |
| permissions **[P1]** | key (`employees:write`), description | unique(key) |
| role_permissions **[P1]** | role_id, permission_id | PK(role_id, permission_id) |
| user_roles **[P1]** | user_id, role_id, granted_by, granted_at | PK(user_id, role_id) |
| user_sessions **[P1]** | user_id, token_hash, csrf_hash, ip, user_agent, created_at, last_seen_at, expires_at, revoked_at, mfa_verified | unique(token_hash); idx(user_id, revoked_at) |
| auth_tokens **[P1]** | user_id, purpose(email_verify/password_reset/invite), token_hash, expires_at, used_at | unique(token_hash) |
| authentication_events **[P1]** | organization_id, user_id NULL, email_attempted, event_type, success, ip, user_agent, reason | idx(organization_id, created_at), idx(ip, created_at) |
| webauthn_credentials | user_id, credential_id bytea, public_key bytea, sign_count, transports, name, last_used_at, revoked_at | unique(credential_id) |

## Workforce

| Table | Key columns | Notes |
|---|---|---|
| employees **[P1]** | organization_id, employee_number, full_name, email, department, job_title, status(invited/active/suspended/offboarded), user_id NULL, manager_id NULL, start_date, end_date | unique(org, employee_number), unique(org, lower(email)) |
| employee_events **[P1]** | employee_id, kind(joiner/mover/leaver/suspend/reactivate), details jsonb, actor_id | JML history |

## Endpoints (Phase 2)

| Table | Key columns |
|---|---|
| devices | organization_id, employee_id NULL, display_name, hostname, os_name, os_version, os_build, manufacturer, model, serial_number, agent_version, status(pending/active/suspended/revoked/unenrolled), enrolled_at, last_heartbeat_at, last_ip, compliance_state(compliant/non_compliant/unknown) |
| enrollment_tokens | organization_id, token_hash, created_by, employee_id NULL, expires_at, used_at, used_by_device_id |
| device_certificates | device_id, serial, fingerprint_sha256 (unique), not_before, not_after, status(active/revoked/expired), revoked_at, revoked_reason |
| device_heartbeats | device_id, received_at, source_ip, agent_version, uptime_seconds — partitioned monthly by received_at |
| device_inventory | device_id, collected_at, cpu jsonb, memory_bytes, disks jsonb, network_interfaces jsonb, raw jsonb (validated & size-capped) |
| agent_versions | version (unique), sha256, signature, channel, released_at, revoked |

## Policy & compliance (Phase 3)

| Table | Key columns |
|---|---|
| endpoint_policies | organization_id, name, description, category(firewall/bitlocker/usb/antivirus/screen_lock/windows_update/password), configuration jsonb (schema-validated per category), version int, created_by, status(draft/active/retired) |
| policy_assignments | policy_id, device_id, assigned_by, assigned_at, revoked_at — unique(policy_id, device_id) where revoked_at is null |
| policy_deployments | assignment_id, policy_version, command_job_id, status(pending/in_progress/applied/failed/offline/needs_attention), result jsonb, previous_state jsonb (for rollback) |
| command_jobs | organization_id, device_id, command, parameters jsonb, nonce (unique), issued_at, expires_at, signature, key_id, status(queued/delivered/succeeded/failed/expired/revoked), idempotency_key (unique), requested_by, result jsonb |
| compliance_checks | organization_id NULL (=built-in), key, name, severity, description, remediation |
| compliance_results | device_id, check_id, evaluated_at, result(PASS/FAIL/UNKNOWN/NOT_APPLICABLE), evidence jsonb — idx(device_id, check_id, evaluated_at desc) |

## Remote admin (Phase 4)
remote_sessions: organization_id, device_id, requested_by, reason, consent_state(pending/granted/denied/expired), consented_at, started_at, ended_at, expires_at, end_reason.

## Applications / SSO (Phase 5)
applications (name, protocol oidc/saml, client_id unique, client_secret_hash, redirect_uris text[], mfa_required, verified_at — set only after a tested login flow), application_assignments (application_id, employee_id, granted_by, revoked_at).

## Security operations
| Table | Key columns |
|---|---|
| security_alerts (P6) | organization_id, rule_key, title, description, severity, device_id NULL, employee_id NULL, detected_at, status(new/triaging/investigating/resolved/false_positive), assigned_to, resolution_notes, dedup_key |
| audit_logs **[P1]** | organization_id, seq bigint (unique per org), actor_user_id NULL, actor_type(user/system/device), action, target_type, target_id, source_ip, result(success/failure/denied), metadata jsonb, prev_hash, hash |
| notifications **[P1 table, P6 delivery]** | organization_id, user_id, kind, title, body, link, read_at |

### Audit chain
`hash = SHA-256(prev_hash || canonical_json(seq, org, actor, action, target, ts, ip, result, metadata))`,
then `HMAC-SHA256(AUDIT_HMAC_KEY, hash)` is stored as `mac` so that an attacker with DB write access but
without the key cannot rebuild a valid chain. The DB role used by the app has `INSERT, SELECT` only on
`audit_logs` (enforced in the Phase 7 role script; a trigger also rejects UPDATE/DELETE).
Limitations are documented in `SECURITY.md`.
