# Security operations: alerts, notifications, reports

## Alert model

Alerts are leads for an analyst, never verdicts. Every alert has a **kind**:

| Kind | Meaning | Example |
|---|---|---|
| `configuration` | A security setting is not as required. Not evidence of compromise. | Firewall disabled |
| `operational` | Something stopped working. | Agent stopped reporting |
| `suspicious_activity` | A pattern worth investigating. | Failed sign-ins across several accounts from one IP |

Open alerts are **de-duplicated** by key (occurrence count and last-seen update instead of new rows; severity can
escalate). Configuration and operational alerts **resolve automatically** when the condition clears, with a note.

## Detection rules

| Rule | Trigger | Severity |
|---|---|---|
| Multiple failed sign-ins | ≥5 failures for one account in 15 min (≥10 → high) | medium/high |
| Password spraying | ≥10 failures from one IP across ≥3 accounts in 15 min | high |
| Successful sign-in after failures | success preceded by ≥3 failures in 15 min | medium |
| Firewall disabled / Antivirus off / BitLocker off | compliance check FAIL (UNKNOWN never alerts) | high / high / medium |
| USB storage connected | storage connection reported; medium if a USB restriction policy is assigned, informational otherwise | medium/info |
| Agent stopped reporting | no authenticated heartbeat for `AGENT_SILENCE_ALERT_MINUTES` (15) | medium |
| Repeated deployment failures | ≥3 failed/attention deployments of one policy on one device in 24 h | medium |
| Unusual administrative activity | ≥5 high-impact actions (revocations, offboardings, role changes, remote restarts…) by one admin in 10 min | high |
| Repeated permission denials | ≥10 `authz.denied` for one account in 10 min | medium |
| Suspicious remote access | ≥3 failed password confirmations for remote actions in 10 min (high); ≥2 refused assistance requests to one device in 1 h (medium) | high/medium |

Event-driven rules run inline (sign-in, inventory/compliance, USB, deployment results). Time-window rules run in the
**scheduler** every 60 s, which also delivers email, expires command jobs and purges old heartbeats. The scheduler
runs inside the API process, guarded by a PostgreSQL advisory lock so only one instance executes it; for production
it can be replaced by Celery beat (`app/workers/celery_app.py`, not verified here — Redis not installed).

## Investigation workflow

`new → triaging → investigating → resolved | false_positive`, reopen from closed → `investigating`. Only accounts with
`alerts:manage` (Super Admin, Security Analyst) can assign or change alerts; Admins can read. Closing requires
resolution notes. Assignment, status changes and notes form the alert history and are audited.

## Notifications

Categories: security alerts, authentication, endpoint enrollment, compliance, policy deployments, agent communication,
employee offboarding, remote sessions, other. Per user and category: in-app on/off + minimum severity, email on/off +
minimum severity (default: in-app everything; email for security alerts, authentication and agent communication from
**high**). Emails are written to `email_outbox` in the same transaction and delivered by the scheduler with
exponential backoff (6 attempts), so a mail outage never silently drops a notification.

## Reports

Endpoint inventory, device compliance, policy deployments, authentication history, audit history, employee access,
security alerts, endpoint health — CSV (UTF-8 with BOM, spreadsheet-formula neutralised) or PDF (landscape table,
organisation / generated-by / period header, row count and page footer). Each report requires `reports:export` plus
the read permission of its data; every export is audited with format, period and row count.
