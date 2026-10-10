from __future__ import annotations

# Adapted from LCIT-Sign (GPL-3.0).

import base64
import hashlib
import hmac
import os

# scrypt (memory-hard, in the standard library): no extra dependency, and a
# stolen database does not yield passwords. Format: scrypt$N$r$p$salt$hash.
_N, _R, _P = 2**15, 8, 1
_KEYLEN = 32

# Passwords that must never protect a production system, however a deployment
# came by them. Development and test environments are not held to this.
WEAK_PASSWORDS = frozenset(
    {
        "admin", "administrator", "password", "password1", "passw0rd", "secret",
        "secretpassword", "changeme", "change-me", "letmein", "welcome", "123456",
        "12345678", "123456789", "qwerty", "azerty", "tlsscan", "tls-scan",
    }
)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=_KEYLEN, maxmem=2**27
    )
    salt_b64 = base64.b64encode(salt).decode()
    digest_b64 = base64.b64encode(digest).decode()
    return f"scrypt${_N}${_R}${_P}${salt_b64}${digest_b64}"


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time check. A missing or malformed hash still costs one scrypt
    run, so response time does not reveal whether an account can log in."""
    try:
        _, n, r, p, salt_b64, digest_b64 = (stored or "").split("$")
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(digest_b64)
        n_, r_, p_ = int(n), int(r), int(p)
    except (ValueError, TypeError):
        n_, r_, p_ = _N, _R, _P
        salt, expected = b"\0" * 16, b"\0" * _KEYLEN
        hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n_, r=r_, p=p_, dklen=_KEYLEN, maxmem=2**27
        )
        return False
    actual = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n_, r=r_, p=p_, dklen=len(expected), maxmem=2**27
    )
    return hmac.compare_digest(actual, expected)


def is_acceptable_for_production(password: str) -> str | None:
    """Why a password is too weak to choose, or None if it is acceptable."""
    if len(password) < 12:
        return "at least 12 characters"
    # "Password1234" is "password" with digits stuck on: compare the letters alone.
    letters = "".join(c for c in password.lower() if c.isalpha())
    if password.lower() in WEAK_PASSWORDS or letters in WEAK_PASSWORDS:
        return "well-known or too common password"
    if len(set(password)) < 6:
        return "too few distinct characters"
    return None
