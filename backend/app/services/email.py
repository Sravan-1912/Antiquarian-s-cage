"""Outbound email. Uses SMTP when configured; in development only, writes .eml files to a local outbox
directory instead (a stand-in for a mail catcher). Never logs token-bearing links."""
from __future__ import annotations

import logging
import smtplib
import ssl
import uuid
from email.message import EmailMessage
from pathlib import Path

from app.core.config import get_settings

log = logging.getLogger(__name__)


class EmailDeliveryError(RuntimeError):
    pass


def send_email(to: str, subject: str, body: str) -> None:
    s = get_settings()
    msg = EmailMessage()
    msg["From"] = s.smtp_from
    msg["To"] = to
    msg["Subject"] = f"[{s.app_name}] {subject}"
    msg.set_content(body)

    if s.smtp_host:
        try:
            with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=10) as smtp:
                if s.smtp_starttls:
                    smtp.starttls(context=ssl.create_default_context())
                if s.smtp_username and s.smtp_password:
                    smtp.login(s.smtp_username, s.smtp_password)
                smtp.send_message(msg)
            log.info("email sent", extra={"event": "email.sent"})
            return
        except (OSError, smtplib.SMTPException) as exc:
            log.exception("email delivery failed")
            raise EmailDeliveryError(str(exc)) from exc

    if s.environment in ("development", "test"):
        outbox = Path(s.dev_outbox_dir)
        outbox.mkdir(parents=True, exist_ok=True)
        path = outbox / f"{uuid.uuid4().hex}.eml"
        path.write_bytes(bytes(msg))
        log.warning("SMTP not configured; email written to dev outbox", extra={"event": "email.outbox"})
        return

    raise EmailDeliveryError("SMTP is not configured")


def link(path: str, token: str) -> str:
    return f"{get_settings().public_base_url.rstrip('/')}{path}?token={token}"
