from __future__ import annotations

import hashlib
import secrets

SESSION_COOKIE = "tls_scan_session"
CSRF_HEADER = "x-csrf-token"


def new_session_token() -> tuple[str, str]:
    """(raw token for the HttpOnly cookie, sha256 stored in the database)."""
    raw = secrets.token_urlsafe(48)
    return raw, hash_session_token(raw)


def hash_session_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)
