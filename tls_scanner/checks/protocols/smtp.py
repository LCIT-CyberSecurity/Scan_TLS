"""SMTP (RFC 3207): EHLO, STARTTLS. Same dialogue as the historical raw probe."""

from __future__ import annotations

from .starttls import NOT_OFFERED, NOT_PROTOCOL, REFUSED, UPGRADED, Upgrade, Wire, WireError, numbered_reply

PROTOCOL = "smtp"


def upgrade(wire: Wire, server_name: str) -> Upgrade:
    try:
        code, _ = numbered_reply(wire)
    except WireError as error:
        if str(error) == "not a numbered reply":
            return Upgrade(NOT_PROTOCOL, PROTOCOL, "the banner is not an SMTP reply")
        raise
    if code != "220":
        return Upgrade(NOT_PROTOCOL if not code.startswith(("4", "5")) else REFUSED, PROTOCOL, f"banner {code}", confirmed=code.startswith(("4", "5")))
    wire.send(b"EHLO tls-scan.invalid\r\n")
    code, lines = numbered_reply(wire)
    advertised = any(line[4:].strip().upper() == "STARTTLS" for line in lines)
    # As historically, STARTTLS is requested even when EHLO did not list it: the server's answer decides.
    wire.send(b"STARTTLS\r\n")
    code, _ = numbered_reply(wire)
    if code == "220":
        return Upgrade(UPGRADED, PROTOCOL, confirmed=True, advertised=True)
    status = NOT_OFFERED if not advertised else REFUSED
    return Upgrade(status, PROTOCOL, f"STARTTLS answered {code}", confirmed=True, advertised=advertised)
