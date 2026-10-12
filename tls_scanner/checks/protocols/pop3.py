"""POP3 (RFC 2595 / 2449): greeting, CAPA, STLS. No USER / PASS."""

from __future__ import annotations

from .starttls import MAX_REPLY_LINES, NOT_OFFERED, NOT_PROTOCOL, REFUSED, UPGRADED, Upgrade, Wire, WireError

PROTOCOL = "pop3"


def _capabilities(wire: Wire) -> set[str] | None:
    """None when the server does not implement CAPA (then STLS is simply tried)."""
    wire.send(b"CAPA\r\n")
    first = wire.read_line()
    if not first.startswith("+OK"):
        return None
    tokens: set[str] = set()
    for _ in range(MAX_REPLY_LINES):
        line = wire.read_line()
        if line == ".":
            return tokens
        tokens.add(line.split(" ", 1)[0].upper())
    raise WireError("reply too long")


def upgrade(wire: Wire, server_name: str) -> Upgrade:
    greeting = wire.read_line()
    if not greeting.startswith(("+OK", "-ERR")):
        return Upgrade(NOT_PROTOCOL, PROTOCOL, "the greeting is neither +OK nor -ERR")
    if greeting.startswith("-ERR"):
        return Upgrade(REFUSED, PROTOCOL, "the server refused the session at the greeting", confirmed=True)
    capabilities = _capabilities(wire)
    advertised = None if capabilities is None else "STLS" in capabilities
    if advertised is False:
        return Upgrade(NOT_OFFERED, PROTOCOL, "STLS is not listed in the CAPA answer", confirmed=True, advertised=False)
    wire.send(b"STLS\r\n")
    answer = wire.read_line()
    if answer.startswith("+OK"):
        return Upgrade(UPGRADED, PROTOCOL, confirmed=True, advertised=advertised)
    if advertised is None:
        return Upgrade(NOT_OFFERED, PROTOCOL, "CAPA is not implemented and STLS was refused", confirmed=True)
    return Upgrade(REFUSED, PROTOCOL, "STLS was refused", confirmed=True, advertised=True)
