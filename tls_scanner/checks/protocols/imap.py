"""IMAP (RFC 9051 / 3501): greeting, CAPABILITY, STARTTLS. No LOGIN, no mailbox command."""

from __future__ import annotations

from .starttls import MAX_REPLY_LINES, NOT_OFFERED, NOT_PROTOCOL, REFUSED, UPGRADED, Upgrade, Wire, WireError

PROTOCOL = "imap"


def _tagged_reply(wire: Wire, tag: str) -> tuple[str, list[str]]:
    """Untagged lines until `<tag> OK|NO|BAD ...`: (status word, untagged lines)."""
    untagged: list[str] = []
    for _ in range(MAX_REPLY_LINES):
        line = wire.read_line()
        if line.startswith(f"{tag} "):
            parts = line.split(" ", 2)
            return (parts[1].upper() if len(parts) > 1 else ""), untagged
        untagged.append(line)
    raise WireError("reply too long")


def upgrade(wire: Wire, server_name: str) -> Upgrade:
    greeting = wire.read_line()
    word = greeting.upper()
    if not word.startswith("* "):
        return Upgrade(NOT_PROTOCOL, PROTOCOL, "the greeting is not an IMAP untagged response")
    if word.startswith("* BYE"):
        return Upgrade(REFUSED, PROTOCOL, "the server closed the session at the greeting", confirmed=True)
    if not word.startswith(("* OK", "* PREAUTH")):
        return Upgrade(NOT_PROTOCOL, PROTOCOL, "the greeting is not an IMAP greeting")
    if word.startswith("* PREAUTH"):
        return Upgrade(NOT_OFFERED, PROTOCOL, "the session is already authenticated (PREAUTH): STARTTLS is not valid", confirmed=True)
    wire.send(b"a001 CAPABILITY\r\n")
    status, lines = _tagged_reply(wire, "a001")
    capabilities = {token.upper() for line in lines if line.upper().startswith("* CAPABILITY") for token in line.split()[2:]}
    if status != "OK" or "STARTTLS" not in capabilities:
        return Upgrade(NOT_OFFERED, PROTOCOL, "STARTTLS is not listed in the CAPABILITY answer", confirmed=True, advertised=False)
    wire.send(b"a002 STARTTLS\r\n")
    status, _ = _tagged_reply(wire, "a002")
    if status == "OK":
        return Upgrade(UPGRADED, PROTOCOL, confirmed=True, advertised=True)
    return Upgrade(REFUSED, PROTOCOL, f"STARTTLS answered {status or 'no status'}", confirmed=True, advertised=True)
