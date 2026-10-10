"""SMTP delivery of queued notifications, and connector diagnostics (readable errors, no secrets)."""
from __future__ import annotations

import logging
import smtplib
import socket
import ssl
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.config import Settings
from tls_scan_app.models import Notification, SystemSetting, User
from tls_scan_app.services.logs import scrub_text

logger = logging.getLogger("tls_scan_app.mail")


def smtp_config(db: DbSession) -> dict[str, Any] | None:
    row = db.get(SystemSetting, "notifications")
    if not row or row.value.get("connector") != "smtp":
        return None
    cfg = row.value.get("smtp", {})
    return cfg if cfg.get("host") and cfg.get("from") else None


def _connect(cfg: dict[str, Any], password: str) -> smtplib.SMTP:
    host, port = cfg["host"], int(cfg.get("port", 587))
    if cfg.get("tls_mode") == "ssl":
        client: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context())
    else:
        client = smtplib.SMTP(host, port, timeout=15)
        client.ehlo()
        if cfg.get("starttls", True):
            client.starttls(context=ssl.create_default_context())  # certificate verified
            client.ehlo()
    if cfg.get("username") and password:
        client.login(cfg["username"], password)
    return client


def diagnose(cfg: dict[str, Any], password: str, to: str | None = None) -> list[dict[str, str]]:
    """Step-by-step connector test: each step reports ok/fail with an actionable explanation."""
    steps: list[dict[str, str]] = []

    def step(name: str, ok: bool, detail: str = "") -> None:
        steps.append({"step": name, "status": "ok" if ok else "fail", "detail": scrub_text(detail)})

    host, port = cfg.get("host", ""), int(cfg.get("port", 587))
    try:
        socket.getaddrinfo(host, port)
        step("dns", True, host)
    except OSError as error:
        step("dns", False, f"Cannot resolve {host!r}: {error}")
        return steps
    try:
        client = _connect(cfg, password)
        step("connect+tls+auth", True)
    except ssl.SSLCertVerificationError as error:
        step("connect+tls+auth", False, f"TLS certificate not trusted: {error.verify_message}. Install the CA or fix the server certificate.")
        return steps
    except smtplib.SMTPAuthenticationError as error:
        step("connect+tls+auth", False, f"Authentication refused ({error.smtp_code}). Check username/password and that SMTP AUTH is enabled.")
        return steps
    except (OSError, smtplib.SMTPException) as error:
        step("connect+tls+auth", False, f"{type(error).__name__}: {error}")
        return steps
    try:
        if to:
            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = cfg["from"], to, "[TLS Scan] SMTP connector test"
            msg.set_content("This is a test message from TLS Scan.")
            client.send_message(msg)
            step("send", True, to)
    except (OSError, smtplib.SMTPException) as error:
        step("send", False, f"{type(error).__name__}: {error}")
    finally:
        try:
            client.quit()
        except Exception:  # noqa: BLE001
            pass
    return steps


def deliver_pending(db: DbSession, settings: Settings, limit: int = 20) -> int:
    pending = db.execute(select(Notification).where(Notification.status == "pending").order_by(Notification.created_at).limit(limit)).scalars().all()
    if not pending:
        return 0
    cfg = smtp_config(db)
    sent = 0
    for note in pending:
        if cfg is None:
            note.status, note.error = "skipped", "no notification connector configured"
            continue
        user = db.get(User, note.user_id)
        if user is None or "@" not in user.email or user.email.endswith("@local"):
            note.status, note.error = "skipped", "recipient has no usable e-mail address"
            continue
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = cfg["from"], user.email, note.subject
        link = settings.public_base_url.rstrip("/")
        msg.set_content(note.body.replace("Run: /", f"Report: {link}/"))
        try:
            client = _connect(cfg, settings.smtp_password)
            try:
                client.send_message(msg)
            finally:
                client.quit()
            note.status, note.sent_at = "sent", datetime.now(UTC)
            sent += 1
        except Exception as error:  # noqa: BLE001
            note.status, note.error = "failed", scrub_text(f"{type(error).__name__}: {error}")[:500]
            logger.warning("notification %s failed: %s", note.id, note.error)
    db.commit()
    return sent
