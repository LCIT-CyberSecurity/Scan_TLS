"""Business audit trail. Secrets must never be passed in `detail`."""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import AuditEvent, User

SENSITIVE_KEYS = ("password", "secret", "token", "cookie", "authorization")


def scrub(detail: dict[str, Any] | None) -> dict[str, Any] | None:
    if not detail:
        return detail
    return {k: ("***" if any(s in k.lower() for s in SENSITIVE_KEYS) else v) for k, v in detail.items()}


def record(
    db: DbSession,
    action: str,
    *,
    actor: User | None = None,
    actor_label: str = "",
    resource_type: str = "",
    resource_id: str | uuid.UUID = "",
    outcome: str = "success",
    detail: dict[str, Any] | None = None,
    ip_address: str = "",
    request_id: str = "",
) -> AuditEvent:
    event = AuditEvent(
        actor_id=actor.id if actor else None,
        actor_label=actor.email if actor else actor_label,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        outcome=outcome,
        detail=scrub(detail),
        ip_address=ip_address,
        request_id=request_id,
    )
    db.add(event)
    return event
