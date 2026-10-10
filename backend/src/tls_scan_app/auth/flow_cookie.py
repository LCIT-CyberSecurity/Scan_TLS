from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

LOGIN_FLOW_COOKIE = "tls_scan_login"
MAX_AGE_SECONDS = 300


def sign(payload: dict[str, Any], secret: str) -> str:
    """Tamper-evident short-lived cookie holding state/nonce/PKCE verifier (HMAC-SHA256)."""
    body = base64.urlsafe_b64encode(json.dumps({**payload, "issued_at": time.time()}).encode()).decode("ascii")
    return f"{body}.{hmac.new(secret.encode(), body.encode('ascii'), hashlib.sha256).hexdigest()}"


def verify(value: str, secret: str) -> dict[str, Any] | None:
    try:
        body, signature = value.split(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(signature, hmac.new(secret.encode(), body.encode("ascii"), hashlib.sha256).hexdigest()):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(body))
    except ValueError:
        return None
    return payload if time.time() - payload.get("issued_at", 0) <= MAX_AGE_SECONDS else None
