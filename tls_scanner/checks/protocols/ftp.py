"""FTP (RFC 4217): greeting, AUTH TLS. No USER / PASS, no data connection, no transfer."""

from __future__ import annotations

from .starttls import NOT_OFFERED, NOT_PROTOCOL, REFUSED, UPGRADED, Upgrade, Wire, WireError, numbered_reply

PROTOCOL = "ftp"


def upgrade(wire: Wire, server_name: str) -> Upgrade:
    try:
        code, _ = numbered_reply(wire)
    except WireError as error:
        if str(error) == "not a numbered reply":
            return Upgrade(NOT_PROTOCOL, PROTOCOL, "the banner is not an FTP reply")
        raise
    if code != "220":
        return Upgrade(REFUSED if code.startswith(("4", "5")) else NOT_PROTOCOL, PROTOCOL, f"banner {code}", confirmed=code.startswith(("4", "5")))
    wire.send(b"AUTH TLS\r\n")
    code, _ = numbered_reply(wire)
    if code == "234":
        return Upgrade(UPGRADED, PROTOCOL, confirmed=True, advertised=True)
    if code in ("500", "502", "504"):
        return Upgrade(NOT_OFFERED, PROTOCOL, f"AUTH TLS is not available (reply {code})", confirmed=True, advertised=False)
    return Upgrade(REFUSED, PROTOCOL, f"AUTH TLS answered {code}", confirmed=True)
