"""
TLS client authentication (mTLS) detection, without any client certificate.

Two observations per TLS version (1.3 then 1.2):
1. `openssl s_client -msg` shows whether the server sent a CertificateRequest during the handshake, and
   which CA names it accepts.
2. A handshake with the Python `ssl` module and *no* client certificate shows whether the server tolerates
   it. In TLS 1.3 the client finishes its handshake before the server verifies it, so the connection is read
   for a short time to catch a post-handshake alert (certificate_required, bad_certificate...).

Outcomes: `none_observed` (no request seen), `requested_optional_or_probable` (a certificate was requested and
the TLS layer accepted the connection without one), `required_demonstrated` (a certificate was requested and the
server rejected the connection without one). A completed handshake does not prove that the application behind it
does not authenticate users, and a failed one does not prove mTLS by itself: the verdict of the application layer
(for instance an HTTP 400 for a missing certificate) is out of reach of a TLS probe.

Client certificates are deliberately not supported here: no key, certificate or secret is read or stored.
"""

from __future__ import annotations

import re
import socket
import ssl
import time

from ..pki import safe_sni_name
from .contracts import INCONCLUSIVE, NOT_APPLICABLE, PASS, CheckContext, CheckResult, result
from .protocols import open_channel
from .sessions import TLS12, TLS13, client_context
from .transport import run_s_client

CHECK_ID = "client_auth"
POST_HANDSHAKE_WAIT_SECONDS = 1.2
MAX_CA_NAMES = 10
MAX_CA_NAME_CHARS = 200
REJECTION_RE = re.compile(r"certificate.required|bad.certificate|unknown.ca|handshake.failure|certificate.unknown|unsupported.certificate|no.certificate|peer did not return a certificate", re.IGNORECASE)


def parse_request(text: str) -> tuple[bool, list[str]]:
    """(CertificateRequest seen, accepted CA names) from an `s_client -msg` transcript."""
    requested = bool(re.search(r"CertificateRequest", text))
    names: list[str] = []
    block = re.search(r"Acceptable client certificate CA names\n(.*?)(?:\n---|\nRequested Signature Algorithms|\nClient Certificate Types|\Z)", text, re.DOTALL)
    if block:
        for line in block.group(1).splitlines():
            line = line.strip()
            if line:
                names.append(line[:MAX_CA_NAME_CHARS])
            if len(names) >= MAX_CA_NAMES:
                break
    return requested, names


def _request_observed(context: CheckContext, version: str):
    flag = "-tls1_3" if version == TLS13 else "-tls1_2"
    output = run_s_client(context, [flag, "-msg"], stdin=b"")
    if not re.search(r"ServerHello|Server Hello", output.text):
        return None, [], output.error or "no ServerHello"
    requested, names = parse_request(output.text)
    return requested, names, ""


def _without_certificate(context: CheckContext, version: str) -> tuple[str, str]:
    """('completed' | 'rejected' | 'closed' | 'error', detail): the handshake with no client certificate."""
    sock, _, error = open_channel(context)
    if sock is None:
        return "error", error
    client = client_context(version, no_ticket=True)
    try:
        sock.settimeout(context.probe_timeout())
        tls = client.wrap_socket(sock, server_hostname=safe_sni_name(context.sni or "") or None)
    except ssl.SSLError as failure:
        sock.close()
        text = str(failure)
        return ("rejected", text[:80]) if REJECTION_RE.search(text) else ("error", f"handshake failed: {failure.__class__.__name__}")
    except OSError as failure:
        sock.close()
        return "error", f"handshake failed: {failure.__class__.__name__}"
    try:
        deadline = time.monotonic() + min(POST_HANDSHAKE_WAIT_SECONDS, max(0.2, context.time_left()))
        while time.monotonic() < deadline:
            tls.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                data = tls.recv(1)
            except (TimeoutError, socket.timeout, ssl.SSLWantReadError):
                break
            except ssl.SSLError as failure:
                text = str(failure)
                return ("rejected", text[:80]) if REJECTION_RE.search(text) else ("error", text[:80])
            except OSError:
                return "closed", "connection reset without alert"
            if not data:
                return "closed", "connection closed without alert"
            # application data from the server: the connection is established, stop reading
            break
        return "completed", ""
    finally:
        tls.close()


def _classify(requested, without: str) -> str:
    if requested is None or without == "error":
        return "undetermined"
    if without == "completed":
        return "requested_optional_or_probable" if requested else "none_observed"
    if without == "rejected":
        return "required_demonstrated" if requested else "undetermined"
    return "undetermined"  # closed without alert


def check_client_auth(context: CheckContext) -> CheckResult:
    versions = [v for v in (TLS13, TLS12) if not context.observed_versions or v in context.observed_versions]
    if not versions:
        return result(CHECK_ID, NOT_APPLICABLE, "The endpoint supports neither TLS 1.2 nor TLS 1.3; client authentication is probed on those versions.")
    by_version: dict[str, dict] = {}
    for version in versions:
        if not context.can_probe():
            break
        requested, names, error = _request_observed(context, version)
        without, detail = ("error", error) if requested is None else _without_certificate(context, version)
        by_version[version] = {
            "certificate_requested": requested,
            "acceptable_ca_names": names,
            "without_certificate": without,
            "detail": detail,
            "outcome": _classify(requested, without),
        }
    outcomes = [item["outcome"] for item in by_version.values()]
    names = sorted({name for item in by_version.values() for name in item["acceptable_ca_names"]})[:MAX_CA_NAMES]
    observations = {
        "outcome": "undetermined", "by_version": by_version, "acceptable_ca_names": names,
        "limit": "no client certificate is ever sent; the application layer may still require or ignore authentication",
    }
    evidence = [f"{v}: requested={item['certificate_requested']}, without certificate={item['without_certificate']}" for v, item in by_version.items()]
    if "required_demonstrated" in outcomes:
        observations["outcome"] = "required_demonstrated"
        return result(CHECK_ID, PASS, "A client certificate is requested and the connection is rejected without one (mTLS required at the TLS layer).", observations, evidence)
    if "requested_optional_or_probable" in outcomes:
        observations["outcome"] = "requested_optional_or_probable"
        return result(CHECK_ID, PASS, "A client certificate is requested but the TLS layer accepted the connection without one (optional, or enforced by the application).", observations, evidence)
    if outcomes and all(outcome == "none_observed" for outcome in outcomes):
        observations["outcome"] = "none_observed"
        return result(CHECK_ID, PASS, "No client certificate request was observed. The application may still authenticate users by other means.", observations, evidence)
    details = "; ".join(sorted({item["detail"] for item in by_version.values() if item["detail"]})) or "no conclusive probe"
    return result(CHECK_ID, INCONCLUSIVE, f"Client authentication could not be determined ({details}).", observations, evidence)
