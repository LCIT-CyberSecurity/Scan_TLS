"""Delivery of queued notifications (SMTP or Microsoft Graph) and connector diagnostics.

Diagnostics return readable steps (never secrets) so an administrator can tell DNS, TLS-certificate,
authentication and permission problems apart.
"""
from __future__ import annotations

import logging
import smtplib
import socket
import ssl
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any, Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.config import Settings
from tls_scan_app.models import Notification, SystemSetting, User
from tls_scan_app.services.logs import scrub_text

logger = logging.getLogger("tls_scan_app.mail")


class Sender(Protocol):
    def send(self, to: str, subject: str, body: str) -> None: ...


def notification_config(db: DbSession) -> dict[str, Any]:
    row = db.get(SystemSetting, "notifications")
    return row.value if row else {"connector": "none"}


def smtp_config(db: DbSession) -> dict[str, Any] | None:
    cfg = notification_config(db)
    smtp = cfg.get("smtp", {})
    return smtp if cfg.get("connector") == "smtp" and smtp.get("host") and smtp.get("from") else None


class SmtpSender:
    def __init__(self, cfg: dict[str, Any], password: str) -> None:
        self.cfg, self.password = cfg, password

    def connect(self) -> smtplib.SMTP:
        host, port = self.cfg["host"], int(self.cfg.get("port", 587))
        if self.cfg.get("tls_mode") == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context())
        else:
            client = smtplib.SMTP(host, port, timeout=15)
            client.ehlo()
            if self.cfg.get("starttls", True):
                client.starttls(context=ssl.create_default_context())  # certificate verified
                client.ehlo()
        if self.cfg.get("username") and self.password:
            client.login(self.cfg["username"], self.password)
        return client

    def send(self, to: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.cfg["from"], to, subject
        msg.set_content(body)
        client = self.connect()
        try:
            client.send_message(msg)
        finally:
            try:
                client.quit()
            except Exception:  # noqa: BLE001
                pass


class GraphSender:
    """Microsoft Graph `sendMail` with the client-credentials flow (application permission Mail.Send)."""

    def __init__(self, cfg: dict[str, Any], secret: str, login_url: str, base_url: str) -> None:
        self.cfg, self.secret, self.login_url, self.base_url = cfg, secret, login_url.rstrip("/"), base_url.rstrip("/")

    def token(self) -> str:
        r = httpx.post(f"{self.login_url}/{self.cfg['tenant_id']}/oauth2/v2.0/token", timeout=15, data={
            "grant_type": "client_credentials", "client_id": self.cfg["client_id"], "client_secret": self.secret,
            "scope": "https://graph.microsoft.com/.default"})
        if r.status_code != 200:
            detail = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            raise RuntimeError(f"token request refused ({r.status_code} {detail.get('error', '')}: {str(detail.get('error_description', ''))[:200]})")
        return r.json()["access_token"]

    def send(self, to: str, subject: str, body: str) -> None:
        r = httpx.post(f"{self.base_url}/users/{self.cfg['sender']}/sendMail", timeout=20, headers={"Authorization": f"Bearer {self.token()}"},
                       json={"message": {"subject": subject, "body": {"contentType": "Text", "content": body}, "toRecipients": [{"emailAddress": {"address": to}}]}, "saveToSentItems": False})
        if r.status_code not in (200, 202):
            raise RuntimeError(f"sendMail refused ({r.status_code}): {r.text[:200]}")


def build_sender(db: DbSession, settings: Settings) -> Sender | None:
    cfg = notification_config(db)
    if cfg.get("connector") == "smtp" and smtp_config(db):
        return SmtpSender(cfg["smtp"], settings.smtp_password)
    graph = cfg.get("graph", {})
    if cfg.get("connector") == "graph" and graph.get("tenant_id") and graph.get("client_id") and graph.get("sender"):
        return GraphSender(graph, settings.graph_client_secret, settings.graph_login_url, settings.graph_base_url)
    return None


def diagnose(db: DbSession, settings: Settings, to: str | None = None) -> list[dict[str, str]]:
    """Step-by-step connector test with an actionable explanation per failure."""
    steps: list[dict[str, str]] = []

    def step(name: str, ok: bool, detail: str = "") -> bool:
        steps.append({"step": name, "status": "ok" if ok else "fail", "detail": scrub_text(detail)})
        return ok

    sender = build_sender(db, settings)
    if sender is None:
        step("configuration", False, "No complete connector configuration (SMTP: host + sender; Graph: tenant, client id, sender mailbox).")
        return steps
    if isinstance(sender, SmtpSender):
        host, port = sender.cfg["host"], int(sender.cfg.get("port", 587))
        try:
            socket.getaddrinfo(host, port)
            step("dns", True, host)
        except OSError as error:
            step("dns", False, f"Cannot resolve {host!r}: {error}")
            return steps
        try:
            client = sender.connect()
            step("connect+tls+auth", True)
            client.quit()
        except ssl.SSLCertVerificationError as error:
            step("connect+tls+auth", False, f"TLS certificate not trusted: {error.verify_message}. Install the CA or fix the server certificate.")
            return steps
        except smtplib.SMTPAuthenticationError as error:
            step("connect+tls+auth", False, f"Authentication refused ({error.smtp_code}). Check username/password and that SMTP AUTH is enabled.")
            return steps
        except (OSError, smtplib.SMTPException) as error:
            step("connect+tls+auth", False, f"{type(error).__name__}: {error}")
            return steps
    else:
        if not settings.graph_client_secret:
            step("secret", False, "TLS_SCAN_GRAPH_CLIENT_SECRET is not set.")
            return steps
        try:
            sender.token()
            step("token", True, "client credentials accepted")
        except httpx.HTTPError as error:
            step("token", False, f"Cannot reach the login endpoint: {type(error).__name__}")
            return steps
        except RuntimeError as error:
            step("token", False, f"{error}. Check tenant id, client id and secret.")
            return steps
    if to:
        try:
            sender.send(to, "[TLS Scan] connector test", "This is a test message from TLS Scan.")
            step("send", True, to)
        except httpx.HTTPError as error:
            step("send", False, f"Graph unreachable: {type(error).__name__}")
        except Exception as error:  # noqa: BLE001
            hint = " Grant the application permission Mail.Send (admin consent) and check the sender mailbox." if "403" in str(error) else ""
            step("send", False, f"{type(error).__name__}: {error}.{hint}")
    return steps


def deliver_pending(db: DbSession, settings: Settings, limit: int = 20) -> int:
    pending = db.execute(select(Notification).where(Notification.status == "pending").order_by(Notification.created_at).limit(limit)).scalars().all()
    if not pending:
        return 0
    sender = build_sender(db, settings)
    sent = 0
    for note in pending:
        if sender is None:
            note.status, note.error = "skipped", "no notification connector configured"
            continue
        user = db.get(User, note.user_id)
        if user is None or "@" not in user.email or user.email.endswith("@local"):
            note.status, note.error = "skipped", "recipient has no usable e-mail address"
            continue
        body = note.body.replace("Run: /", f"Report: {settings.public_base_url.rstrip('/')}/")
        try:
            sender.send(user.email, note.subject, body)
            note.status, note.sent_at = "sent", datetime.now(UTC)
            sent += 1
        except Exception as error:  # noqa: BLE001
            note.status, note.error = "failed", scrub_text(f"{type(error).__name__}: {error}")[:500]
            logger.warning("notification %s failed: %s", note.id, note.error)
    db.commit()
    return sent
