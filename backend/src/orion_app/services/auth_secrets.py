"""The Microsoft Entra client secret an administrator enters in Administration -> Authentication.

Stored like the GMP password (LST-24): encrypted with the deployment credential key, a protected secret file outside the
database (`ORION_GREENBONE_CREDENTIAL_KEY_FILE`), in its own `system_settings` row so that the authentication settings
the API returns never carry it, not even encrypted. A secret entered here takes precedence over the server's
`ORION_OIDC_CLIENT_SECRET` (or `_FILE`), which stays the fallback: when the stored value cannot be decrypted (key missing
or replaced), the server secret is used instead of breaking the sign-in. The value is never returned, logged or audited.
"""
from __future__ import annotations

import logging
from typing import Any

from orion_app.models import SystemSetting
from orion_app.services import greenbone

SETTING_KEY = "auth_secrets"
ENTRA_FIELD = "entra_client_secret"
MAX_LENGTH = 512

logger = logging.getLogger("orion_app.auth_secrets")


class SecretError(ValueError):
    """A refusal whose message is safe to show (it never contains the secret)."""


class KeyUnavailable(SecretError):
    """The deployment credential key is missing or invalid: nothing can be encrypted or decrypted."""


def _stored(db: Any) -> dict:
    row = db.get(SystemSetting, SETTING_KEY, populate_existing=True)
    return dict(row.value) if row and isinstance(row.value, dict) else {}


def _cipher(settings: Any):
    try:
        return greenbone.credential_cipher(settings)
    except greenbone.GreenboneError:
        raise KeyUnavailable("The credential encryption key is unavailable on the server (ORION_GREENBONE_CREDENTIAL_KEY_FILE): "
                          "the secret cannot be stored. Set ORION_OIDC_CLIENT_SECRET_FILE instead.") from None


def validate(value: str) -> str:
    if not value:
        raise SecretError("Enter the client secret value")
    if len(value) > MAX_LENGTH:
        raise SecretError(f"The client secret is longer than {MAX_LENGTH} characters")
    if value != value.strip() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise SecretError("The client secret must not contain spaces at either end nor control characters")
    return value


def store_entra(db: Any, settings: Any, value: str) -> None:
    token = _cipher(settings).encrypt(validate(value).encode()).decode("ascii")
    row = db.get(SystemSetting, SETTING_KEY) or SystemSetting(key=SETTING_KEY, value={})
    row.value = {**_stored(db), ENTRA_FIELD: token}
    db.add(row)


def remove_entra(db: Any) -> bool:
    stored = _stored(db)
    if ENTRA_FIELD not in stored:
        return False
    row = db.get(SystemSetting, SETTING_KEY)
    row.value = {k: v for k, v in stored.items() if k != ENTRA_FIELD}
    db.add(row)
    return True


def entra_secret(db: Any, settings: Any) -> tuple[str, str, bool]:
    """(secret, source, unreadable): source is "webui", "server" or "" (none); unreadable when a stored value exists but cannot
    be decrypted, in which case the server secret, if any, is returned."""
    from cryptography.fernet import InvalidToken

    token = _stored(db).get(ENTRA_FIELD)
    if token:
        try:
            return _cipher(settings).decrypt(token.encode("ascii")).decode(), "webui", False
        except (SecretError, InvalidToken, UnicodeError):  # key missing or replaced, damaged value
            logger.warning("The stored Entra client secret cannot be decrypted; using the server secret if one is set")
            server = settings.oidc_client_secret
            return server, "server" if server else "", True
    server = settings.oidc_client_secret
    return server, "server" if server else "", False


def entra_status(db: Any, settings: Any) -> dict[str, Any]:
    secret, source, unreadable = entra_secret(db, settings)
    return {"configured": bool(secret), "source": source, "unreadable": unreadable, "stored": bool(_stored(db).get(ENTRA_FIELD))}
