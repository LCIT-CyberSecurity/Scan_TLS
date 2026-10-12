"""XMPP client-to-server (RFC 6120): stream header, <starttls/> feature, <proceed/>.

Limit: only the client-to-server stream (`jabber:client`) is spoken; server-to-server (port 5269) is not covered."""

from __future__ import annotations

import re
from xml.sax.saxutils import quoteattr

from .starttls import NOT_OFFERED, NOT_PROTOCOL, REFUSED, UPGRADED, Upgrade, Wire

PROTOCOL = "xmpp"
STREAM_END = (b"</stream:features>", b"<stream:features/>")
STARTTLS_FEATURE = re.compile(rb"<starttls\b[^>]*xmlns=['\"]urn:ietf:params:xml:ns:xmpp-tls['\"]", re.IGNORECASE)


def upgrade(wire: Wire, server_name: str) -> Upgrade:
    domain = quoteattr(server_name or "localhost")
    wire.send(
        b"<?xml version='1.0'?><stream:stream to=" + domain.encode("ascii", "ignore")
        + b" xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )
    opening = wire.read_until(STREAM_END)
    if b"<stream:stream" not in opening and b"<stream:features" not in opening:
        return Upgrade(NOT_PROTOCOL, PROTOCOL, "the answer is not an XMPP stream")
    if not STARTTLS_FEATURE.search(opening):
        return Upgrade(NOT_OFFERED, PROTOCOL, "the stream features do not include STARTTLS", confirmed=True, advertised=False)
    wire.send(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    answer = wire.read_until((b"/>", b"</failure>"))
    if b"<proceed" in answer:
        return Upgrade(UPGRADED, PROTOCOL, confirmed=True, advertised=True)
    return Upgrade(REFUSED, PROTOCOL, "the server did not answer <proceed/>", confirmed=True, advertised=True)
