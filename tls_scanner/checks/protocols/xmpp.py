"""XMPP (RFC 6120): stream header, <starttls/> feature, <proceed/>.

Two adapters share the dialogue: client-to-server (`jabber:client`, port 5222) and server-to-server (`jabber:server`,
port 5269). Neither authenticates, sends a stanza or opens a dialback."""

from __future__ import annotations

import re
from xml.sax.saxutils import quoteattr

from .starttls import NOT_OFFERED, NOT_PROTOCOL, REFUSED, UPGRADED, Upgrade, Wire

PROTOCOL = "xmpp"
PROTOCOL_SERVER = "xmpp_server"
STREAM_END = (b"</stream:features>", b"<stream:features/>")
STARTTLS_FEATURE = re.compile(rb"<starttls\b[^>]*xmlns=['\"]urn:ietf:params:xml:ns:xmpp-tls['\"]", re.IGNORECASE)


def _negotiate(wire: Wire, server_name: str, protocol: str, namespace: str) -> Upgrade:
    domain = quoteattr(server_name or "localhost")
    wire.send(
        b"<?xml version='1.0'?><stream:stream to=" + domain.encode("ascii", "ignore")
        + b" xmlns='" + namespace.encode() + b"' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )
    opening = wire.read_until(STREAM_END)
    if b"<stream:stream" not in opening and b"<stream:features" not in opening:
        return Upgrade(NOT_PROTOCOL, protocol, "the answer is not an XMPP stream")
    if not STARTTLS_FEATURE.search(opening):
        return Upgrade(NOT_OFFERED, protocol, "the stream features do not include STARTTLS", confirmed=True, advertised=False)
    wire.send(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    answer = wire.read_until((b"/>", b"</failure>"))
    if b"<proceed" in answer:
        return Upgrade(UPGRADED, protocol, confirmed=True, advertised=True)
    return Upgrade(REFUSED, protocol, "the server did not answer <proceed/>", confirmed=True, advertised=True)


def upgrade(wire: Wire, server_name: str) -> Upgrade:
    return _negotiate(wire, server_name, PROTOCOL, "jabber:client")


def upgrade_server(wire: Wire, server_name: str) -> Upgrade:
    return _negotiate(wire, server_name, PROTOCOL_SERVER, "jabber:server")
