"""
STARTTLS adapters (SMTP, IMAP, POP3, LDAP, FTP, PostgreSQL, XMPP) and the connection helper used by the checks.

`open_channel` returns a socket on which the TLS handshake can start: a plain connection for direct TLS, or
a connection upgraded by the adapter of the endpoint's protocol. Everything is bounded by the check context
(timeout, remaining budget, cancellation) and the socket is always closed by the caller.
"""

from __future__ import annotations

import socket
import time
from typing import Callable

from . import ftp, imap, ldap, pop3, postgres, smtp, xmpp
from .starttls import ERROR, NOT_PROTOCOL, UPGRADED, Upgrade, Wire, WireError

ADAPTERS: dict[str, Callable[[Wire, str], Upgrade]] = {
    smtp.PROTOCOL: smtp.upgrade,
    imap.PROTOCOL: imap.upgrade,
    pop3.PROTOCOL: pop3.upgrade,
    ldap.PROTOCOL: ldap.upgrade,
    ftp.PROTOCOL: ftp.upgrade,
    postgres.PROTOCOL: postgres.upgrade,
    xmpp.PROTOCOL: xmpp.upgrade,
    xmpp.PROTOCOL_SERVER: xmpp.upgrade_server,
}
# Opt-in protocols of the lot 2 (SMTP is historical and always active on its ports).
OPT_IN_PROTOCOLS = ("imap", "pop3", "ldap", "ftp", "postgres", "xmpp", "xmpp_server")
STANDARD_PORTS: dict[str, tuple[int, ...]] = {
    "smtp": (25, 587),
    "imap": (143,),
    "pop3": (110,),
    "ldap": (389,),
    "ftp": (21,),
    "postgres": (5432,),
    "xmpp": (5222,),
    "xmpp_server": (5269,),
}
# `openssl s_client -starttls` names, for the checks that rely on s_client
S_CLIENT_NAMES = {"smtp": "smtp", "imap": "imap", "pop3": "pop3", "ldap": "ldap", "ftp": "ftp", "postgres": "postgres", "xmpp": "xmpp", "xmpp_server": "xmpp-server"}


def negotiate(protocol: str, sock: socket.socket, deadline: float, server_name: str = "", cancelled: Callable[[], bool] = lambda: False) -> Upgrade:
    """Run the adapter on a connected socket. Never raises: timeouts and malformed answers become `error`."""
    adapter = ADAPTERS.get(protocol)
    if adapter is None:
        return Upgrade(ERROR, protocol, "unknown STARTTLS protocol")
    try:
        return adapter(Wire(sock, deadline, cancelled), server_name)
    except WireError as error:
        return Upgrade(ERROR, protocol, str(error))
    except (IndexError, ValueError, UnicodeError):
        return Upgrade(ERROR, protocol, "malformed answer")


def open_channel(context, deadline: float | None = None) -> tuple[socket.socket | None, Upgrade | None, str]:
    """Connect to the endpoint (and upgrade it when it is a STARTTLS service).

    Returns (socket, upgrade, error). `socket` is None when the connection or the upgrade failed; `upgrade`
    is None for direct TLS. The caller owns the socket.
    """
    deadline = deadline if deadline is not None else time.monotonic() + context.probe_timeout()
    try:
        sock = socket.create_connection((context.host, context.port), timeout=max(0.5, min(context.probe_timeout(), deadline - time.monotonic())))
    except (OSError, TimeoutError) as error:
        return None, None, f"connection failed: {error.__class__.__name__}"
    protocol = context.starttls
    if not protocol:
        return sock, None, ""
    outcome = negotiate(protocol, sock, deadline, context.sni or context.host, context.cancelled)
    if outcome.status != UPGRADED:
        sock.close()
        return None, outcome, f"STARTTLS {protocol}: {outcome.status}" + (f" ({outcome.detail})" if outcome.detail else "")
    return sock, outcome, ""


def ports_for(protocol: str, options: dict | None = None) -> tuple[int, ...]:
    configured = (options or {}).get("ports")
    return tuple(configured) if configured else STANDARD_PORTS.get(protocol, ())


def resolve_protocol(port: int, selected, options: dict[str, dict] | None = None) -> str:
    """STARTTLS protocol assumed for an endpoint: SMTP on its historical ports, an opt-in protocol on
    its (standard or configured) ports when its `starttls_<protocol>` check is selected, else none."""
    if int(port) in STANDARD_PORTS["smtp"]:
        return "smtp"
    for protocol in OPT_IN_PROTOCOLS:
        if f"starttls_{protocol}" in set(selected) and int(port) in ports_for(protocol, (options or {}).get(f"starttls_{protocol}")):
            return protocol
    return ""
