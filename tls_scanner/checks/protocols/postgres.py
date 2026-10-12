"""PostgreSQL: native SSLRequest (not a text STARTTLS). The server answers one byte: S, N or an error."""

from __future__ import annotations

from .starttls import NOT_OFFERED, NOT_PROTOCOL, REFUSED, UPGRADED, Upgrade, Wire

PROTOCOL = "postgres"
SSL_REQUEST = bytes([0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F])  # length 8, code 80877103


def upgrade(wire: Wire, server_name: str) -> Upgrade:
    wire.send(SSL_REQUEST)
    answer = wire.read_exact(1)
    if answer == b"S":
        return Upgrade(UPGRADED, PROTOCOL, confirmed=True, advertised=True)
    if answer == b"N":
        return Upgrade(NOT_OFFERED, PROTOCOL, "the server answered N: SSL is not available", confirmed=True, advertised=False)
    if answer == b"E":
        return Upgrade(REFUSED, PROTOCOL, "the server answered with an error message", confirmed=True)
    return Upgrade(NOT_PROTOCOL, PROTOCOL, "the answer to SSLRequest is not S, N or E")
