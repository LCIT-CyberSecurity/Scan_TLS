"""LDAP StartTLS extended operation (RFC 4511 §4.14, OID 1.3.6.1.4.1.1466.20037). No bind, no search."""

from __future__ import annotations

from .starttls import NOT_PROTOCOL, REFUSED, UPGRADED, Upgrade, Wire

PROTOCOL = "ldap"
START_TLS_OID = b"1.3.6.1.4.1.1466.20037"
# LDAPMessage { messageID 1, extendedReq [APPLICATION 23] { requestName [0] OID } }
START_TLS_REQUEST = bytes([0x30, 0x1D, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16]) + START_TLS_OID
MAX_MESSAGE_BYTES = 4096
RESULT_CODES = {0: "success", 1: "operationsError", 2: "protocolError", 50: "insufficientAccessRights", 51: "busy", 52: "unavailable", 53: "unwillingToPerform"}


def _read_length(wire: Wire) -> int | None:
    first = wire.read_exact(1)[0]
    if first < 0x80:
        return first
    count = first & 0x7F
    if count == 0 or count > 2:
        return None  # indefinite or implausible length
    return int.from_bytes(wire.read_exact(count), "big")


def upgrade(wire: Wire, server_name: str) -> Upgrade:
    wire.send(START_TLS_REQUEST)
    if wire.read_exact(1) != b"\x30":
        return Upgrade(NOT_PROTOCOL, PROTOCOL, "the answer is not an LDAPMessage")
    length = _read_length(wire)
    if length is None or not 5 <= length <= MAX_MESSAGE_BYTES:
        return Upgrade(NOT_PROTOCOL, PROTOCOL, "the LDAPMessage length is not plausible")
    body = wire.read_exact(length)
    # messageID INTEGER, then protocolOp: extendedResp is [APPLICATION 24] = 0x78 carrying the LDAPResult
    if body[0] != 0x02 or len(body) < 3:
        return Upgrade(NOT_PROTOCOL, PROTOCOL, "the LDAPMessage has no message identifier")
    position = 2 + body[1]
    if position >= len(body) or body[position] != 0x78:
        return Upgrade(NOT_PROTOCOL, PROTOCOL, "the answer is not an extended response")
    inner = body[position + 1:]  # length of the protocolOp, then the LDAPResult fields
    start = 0 if not inner else (1 if inner[0] < 0x80 else 1 + (inner[0] & 0x7F))
    result_code = None
    if len(inner) > start + 2 and inner[start] == 0x0A and inner[start + 1] == 0x01:  # resultCode ENUMERATED
        result_code = inner[start + 2]
    if result_code is None:
        return Upgrade(NOT_PROTOCOL, PROTOCOL, "the extended response has no result code")
    if result_code == 0:
        return Upgrade(UPGRADED, PROTOCOL, confirmed=True, advertised=True)
    return Upgrade(REFUSED, PROTOCOL, f"StartTLS refused: {RESULT_CODES.get(result_code, 'resultCode ' + str(result_code))}", confirmed=True, advertised=result_code != 2)
