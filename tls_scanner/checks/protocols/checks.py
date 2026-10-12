"""One check per opt-in STARTTLS protocol: did the service really switch to TLS on a negotiated channel?"""

from __future__ import annotations

import socket
import ssl

from ...pki import safe_sni_name
from ..contracts import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, CheckContext, CheckFunction, CheckResult, result
from . import STANDARD_PORTS, open_channel
from .starttls import ERROR, NOT_OFFERED, NOT_PROTOCOL, REFUSED


def check_id(protocol: str) -> str:
    return f"starttls_{protocol}"


def applies(protocol: str):
    """Protocol checks only exist on the endpoints whose (standard or configured) port belongs to the protocol."""
    return lambda context: context.starttls == protocol


def _tls_after_upgrade(context: CheckContext, sock: socket.socket) -> tuple[dict, str]:
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    try:
        client.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        sock.settimeout(context.probe_timeout())
        tls = client.wrap_socket(sock, server_hostname=safe_sni_name(context.sni or "") or None)
    except (ssl.SSLError, OSError) as failure:
        sock.close()
        return {}, failure.__class__.__name__
    try:
        cipher = tls.cipher()
        return {"tls_version": tls.version(), "cipher_suite": cipher[0] if cipher else None}, ""
    finally:
        tls.close()


def make_check(protocol: str) -> CheckFunction:
    identifier = check_id(protocol)

    def run(context: CheckContext) -> CheckResult:
        configured = bool(context.option("ports"))
        base = {"protocol": protocol, "port": context.port, "assumed_by": "configured ports" if configured else "standard port", "standard_ports": list(STANDARD_PORTS[protocol])}
        sock, upgrade, error = open_channel(context)
        if sock is None and upgrade is None:
            return result(identifier, INCONCLUSIVE, f"{protocol.upper()} STARTTLS could not be examined ({error}).", {**base, "confirmed": False})
        if sock is None:
            observations = {**base, "confirmed": upgrade.confirmed, "advertised": upgrade.advertised, "upgraded": False, "detail": upgrade.detail}
            evidence = [f"{protocol}: {upgrade.status}" + (f" ({upgrade.detail})" if upgrade.detail else "")]
            if upgrade.status == NOT_PROTOCOL:
                return result(identifier, NOT_APPLICABLE, f"The service on this port does not answer like {protocol.upper()}: the protocol was assumed from the port and could not be confirmed.", observations, evidence)
            if upgrade.status in (NOT_OFFERED, REFUSED):
                return result(identifier, FAIL, f"{protocol.upper()} was confirmed but the server did not switch to TLS ({upgrade.detail or upgrade.status}); the connection stays in clear text.", observations, evidence)
            return result(identifier, INCONCLUSIVE, f"The {protocol.upper()} STARTTLS exchange did not complete ({upgrade.detail or ERROR}).", observations, evidence)
        details, failure = _tls_after_upgrade(context, sock)
        observations = {**base, "confirmed": True, "advertised": upgrade.advertised, "upgraded": True, **details}
        if failure:
            return result(identifier, INCONCLUSIVE, f"The server agreed to STARTTLS but the TLS handshake failed ({failure}).", observations)
        return result(identifier, PASS, f"{protocol.upper()} confirmed and switched to TLS with STARTTLS ({details['tls_version']}).", observations, [f"{protocol}: upgraded, {details['tls_version']}"])

    return run
