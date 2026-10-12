"""
A2 - OCSP stapling (a response presented by the server in the handshake).

Distinct from the online OCSP query made by the certificate revocation control: here the server
itself must deliver a fresh, correctly signed response for its own certificate.

Method:
- TLS <= 1.2: a raw ClientHello with status_request; the CertificateStatus message is read, parsed
  with `cryptography` and checked (status, serial, freshness, signature by the issuer or a delegated
  responder).
- TLS 1.3 only servers: the staple is inside the encrypted Certificate message. `openssl s_client -msg` prints that
  message decrypted, so it is parsed like the TLS 1.2 one (certificate chain + CertificateStatus) and verified the same
  way, signature included. If the transcript cannot be parsed, `-status` text output is the fallback: status and
  freshness are read from it but the signature is NOT verified (reported as such).
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509 import ocsp

from ..pki import extension_value, ocsp_urls, verify_ocsp_response_signature
from .protocols import ADAPTERS, S_CLIENT_NAMES
from .contracts import FAIL, INCONCLUSIVE, NOT_APPLICABLE, NOT_TESTED, PASS, CheckContext, CheckResult, result
from .transport import (
    EXT_STATUS_REQUEST,
    HANDSHAKE_CERTIFICATE,
    HANDSHAKE_CERTIFICATE_STATUS,
    run_s_client,
    send_client_hello,
)

CHECK_ID = "ocsp_stapling"
CLOCK_SKEW = timedelta(minutes=5)
SECOND_ATTEMPT_DELAY_SECONDS = 1.5  # servers that fetch their OCSP response lazily staple from the 2nd connection


def parse_certificate_message(body: bytes) -> list[x509.Certificate]:
    certificates = []
    try:
        total = int.from_bytes(body[0:3], "big")
        position, end = 3, min(len(body), 3 + total)
        while position + 3 <= end:
            length = int.from_bytes(body[position:position + 3], "big")
            certificates.append(x509.load_der_x509_certificate(body[position + 3:position + 3 + length]))
            position += 3 + length
    except (ValueError, IndexError):
        return certificates
    return certificates


def staple_from_status_message(body: bytes) -> bytes | None:
    """CertificateStatus = status_type(1) + opaque response<1..2^24-1>."""
    if len(body) < 4 or body[0] != 1:
        return None
    length = int.from_bytes(body[1:4], "big")
    return body[4:4 + length] or None


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def evaluate_staple(der: bytes, leaf: x509.Certificate, issuer: x509.Certificate | None, now: datetime | None = None) -> tuple[str, str, dict]:
    """Return (status, message, observations) for a stapled DER OCSP response."""
    now = now or datetime.now(timezone.utc)
    observations: dict = {"stapling": "present"}
    try:
        response = ocsp.load_der_ocsp_response(der)
    except ValueError as error:
        return FAIL, f"The stapled OCSP response cannot be parsed: {error}", {**observations, "response": "invalid"}
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return FAIL, f"The stapled OCSP response has the status {response.response_status.name}.", {**observations, "response": "invalid", "response_status": response.response_status.name}
    if response.serial_number != leaf.serial_number:
        return FAIL, "The stapled OCSP response is for another certificate.", {**observations, "response": "invalid", "reason": "serial_mismatch"}
    this_update = _as_utc(getattr(response, "this_update_utc", None) or response.this_update)
    next_update = _as_utc(getattr(response, "next_update_utc", None) or response.next_update)
    observations.update(this_update=this_update.isoformat() if this_update else None, next_update=next_update.isoformat() if next_update else None)
    if this_update and this_update - CLOCK_SKEW > now:
        return FAIL, "The stapled OCSP response is not yet valid (thisUpdate in the future).", {**observations, "response": "invalid", "reason": "not_yet_valid"}
    if next_update and next_update + CLOCK_SKEW < now:
        return FAIL, "The stapled OCSP response has expired (nextUpdate in the past).", {**observations, "response": "expired", "reason": "expired"}
    cert_status = response.certificate_status.name.lower()
    observations["certificate_status"] = cert_status
    if issuer is None:
        return INCONCLUSIVE, "The issuer certificate was not presented, so the signature of the stapled response cannot be verified.", {**observations, "signature_verified": False}
    if not verify_ocsp_response_signature(response, issuer):
        return FAIL, "The signature of the stapled OCSP response is not valid for the issuer or a delegated responder.", {**observations, "response": "invalid", "signature_verified": False, "reason": "bad_signature"}
    observations.update(response="valid", signature_verified=True)
    if response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        return FAIL, "The server staples a valid OCSP response saying its certificate is revoked.", observations
    if response.certificate_status == ocsp.OCSPCertStatus.UNKNOWN:
        return FAIL, "The stapled OCSP response reports the certificate as unknown to the responder.", observations
    return PASS, "The server staples a valid, current OCSP response with the status good.", observations


MSG_HEX_LINE = re.compile(r"^ {4}((?:[0-9a-f]{2} ?)+)$")
EXT_STATUS_REQUEST_CODE = 5


def parse_tls13_certificate_message(text: str):
    """Chain and leaf staple from the `<<< TLS 1.3 ... Certificate` hex dump of `openssl s_client -msg`.

    Returns (certificates, staple DER or None), or None when the transcript has no parsable Certificate message."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not (line.startswith("<<<") and line.rstrip().endswith("Certificate")):  # not CertificateRequest / CertificateVerify
            continue
        dump = []
        for following in lines[index + 1:]:
            match = MSG_HEX_LINE.match(following)
            if not match:
                break
            dump.append(match.group(1).replace(" ", ""))
        try:
            body = bytes.fromhex("".join(dump))
            return _certificates_and_staple(body)
        except (ValueError, IndexError):
            return None
    return None


def _certificates_and_staple(body: bytes):
    if len(body) < 8 or body[0] != HANDSHAKE_CERTIFICATE:
        raise ValueError("not a Certificate message")
    position = 4 + 1 + body[4]  # handshake header, certificate_request_context
    list_end = min(len(body), position + 3 + int.from_bytes(body[position:position + 3], "big"))
    position += 3
    certificates, staple, first = [], None, True
    while position + 3 <= list_end:
        length = int.from_bytes(body[position:position + 3], "big")
        certificates.append(x509.load_der_x509_certificate(body[position + 3:position + 3 + length]))
        position += 3 + length
        extensions_length = int.from_bytes(body[position:position + 2], "big")
        extensions_end = position + 2 + extensions_length
        position += 2
        while position + 4 <= extensions_end:
            code, size = int.from_bytes(body[position:position + 2], "big"), int.from_bytes(body[position + 2:position + 4], "big")
            if first and code == EXT_STATUS_REQUEST_CODE:
                staple = staple_from_status_message(body[position + 4:position + 4 + size])
            position += 4 + size
        position = extensions_end
        first = False
    if not certificates:
        raise ValueError("no certificate")
    return certificates, staple


def _tls13_message_path(context: CheckContext):
    """('error'|'absent'|'present', chain, der, detail) from the decrypted TLS 1.3 Certificate message, or None to fall back."""
    output = run_s_client(context, ["-tls1_3", "-status", "-msg"], stdin=b"")
    if output.timed_out or output.error:
        return "error", [], None, output.error or "timeout"
    if not output.connected:
        return "error", [], None, "TLS 1.3 handshake failed"
    parsed = parse_tls13_certificate_message(output.text)
    if parsed is None:
        return None
    chain, der = parsed
    return ("present" if der else "absent"), chain, der, ""


def _issuer_of(leaf: x509.Certificate, chain: list[x509.Certificate]) -> x509.Certificate | None:
    for candidate in chain[1:]:
        if candidate.subject == leaf.issuer:
            return candidate
    return None


def _raw_tls12_staple(context: CheckContext):
    """Returns ('error'|'no_tls12'|'absent'|'present', chain, der, detail)."""
    reply = send_client_hello(context, status_request=True)
    if reply.kind == "alert" or (reply.kind == "error" and not reply.error.startswith("timeout")):
        return "no_tls12", [], None, f"alert {reply.alert}" if reply.alert is not None else reply.error
    if reply.kind != "server_hello":
        return "error", [], None, reply.error or reply.kind
    chain = parse_certificate_message(reply.messages.get(HANDSHAKE_CERTIFICATE, b""))
    if not reply.has_extension(EXT_STATUS_REQUEST) or HANDSHAKE_CERTIFICATE_STATUS not in reply.messages:
        return "absent", chain, None, ""
    der = staple_from_status_message(reply.messages[HANDSHAKE_CERTIFICATE_STATUS])
    return ("present" if der else "absent"), chain, der, ""


def _tls13_status_text(context: CheckContext):
    """Parse `openssl s_client -tls1_3 -status`. Returns (kind, observations, message)."""
    output = run_s_client(context, ["-tls1_3", "-status"], stdin=b"")
    if output.timed_out or output.error:
        return "error", {}, output.error or "timeout"
    if not output.connected:
        return "error", {}, "TLS 1.3 handshake failed"
    if re.search(r"OCSP response:\s*no response sent", output.text, re.IGNORECASE):
        return "absent", {}, ""
    if "OCSP Response Data" not in output.text:
        return "absent", {}, ""
    values = {
        "response_status": re.search(r"OCSP Response Status:\s*(\w+)", output.text),
        "certificate_status": re.search(r"Cert Status:\s*(\w+)", output.text),
        "this_update": re.search(r"This Update:\s*(.+)", output.text),
        "next_update": re.search(r"Next Update:\s*(.+)", output.text),
    }
    return "present", {key: match.group(1).strip() for key, match in values.items() if match}, ""


def _parse_openssl_time(text: str) -> datetime | None:
    try:
        return datetime.strptime(text.replace("  ", " "), "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def check_ocsp_stapling(context: CheckContext) -> CheckResult:
    if context.starttls and context.starttls not in ADAPTERS:
        return result(CHECK_ID, NOT_TESTED, f"STARTTLS {context.starttls} is not supported by this check")
    kind, chain, der, detail = _raw_tls12_staple(context)
    if kind == "absent":
        time.sleep(min(SECOND_ATTEMPT_DELAY_SECONDS, max(0.0, context.time_left() - 1)))
        kind, chain, der, detail = _raw_tls12_staple(context) if context.can_probe() else (kind, chain, der, detail)
    leaf = chain[0] if chain else None
    must_staple = False
    if leaf is not None:
        features = extension_value(leaf, x509.TLSFeature)
        must_staple = bool(features and x509.TLSFeatureType.status_request in features)
        if not ocsp_urls(leaf) and kind != "present":
            return result(CHECK_ID, NOT_APPLICABLE, "The certificate has no OCSP responder URL (AIA), so stapling is not expected.",
                          {"stapling": "absent", "ocsp_url_in_certificate": False})

    if kind == "present" and der and leaf is not None:
        status, message, observations = evaluate_staple(der, leaf, _issuer_of(leaf, chain))
        observations.update(tls_version="TLSv1.2 or lower", must_staple=must_staple)
        return result(CHECK_ID, status, message, observations, [f"OCSP response {len(der)} bytes", f"status: {observations.get('certificate_status', 'n/a')}"])
    if kind == "absent":
        observations = {"stapling": "absent", "must_staple": must_staple, "attempts": 2}
        message = "The server does not staple an OCSP response" + (" although the certificate requires it (must-staple)." if must_staple else ".")
        return result(CHECK_ID, FAIL, message, observations, ["no CertificateStatus message in two handshakes"])

    # no TLS <= 1.2: only TLS 1.3 can tell, and its staple is encrypted
    if "TLSv1.3" in context.observed_versions or kind == "no_tls12":
        message_path = _tls13_message_path(context)
        if message_path is not None and message_path[0] != "error":
            kind13, chain13, der13, _ = message_path
            leaf13 = chain13[0]
            must_staple13 = bool((features := extension_value(leaf13, x509.TLSFeature)) and x509.TLSFeatureType.status_request in features)
            if kind13 == "present":
                status, message, observations = evaluate_staple(der13, leaf13, _issuer_of(leaf13, chain13))
                observations.update(tls_version="TLSv1.3", must_staple=must_staple13, source="decrypted Certificate message (openssl -msg)")
                return result(CHECK_ID, status, message, observations, [f"OCSP response {len(der13)} bytes", f"status: {observations.get('certificate_status', 'n/a')}"])
            if not ocsp_urls(leaf13):
                return result(CHECK_ID, NOT_APPLICABLE, "The certificate has no OCSP responder URL (AIA), so stapling is not expected.", {"stapling": "absent", "ocsp_url_in_certificate": False, "tls_version": "TLSv1.3"})
            return result(CHECK_ID, FAIL, "The TLS 1.3 server does not staple an OCSP response" + (" although the certificate requires it (must-staple)." if must_staple13 else "."),
                          {"stapling": "absent", "tls_version": "TLSv1.3", "must_staple": must_staple13}, ["no status_request extension in the TLS 1.3 Certificate message"])
        text_kind, values, text_detail = _tls13_status_text(context)
        if text_kind == "absent":
            return result(CHECK_ID, FAIL, "The TLS 1.3 server does not staple an OCSP response.", {"stapling": "absent", "tls_version": "TLSv1.3"}, ["no OCSP response in the TLS 1.3 handshake"])
        if text_kind == "present":
            status, message = _tls13_verdict(values)
            observations = {"stapling": "present", "tls_version": "TLSv1.3", "signature_verified": False,
                            "limit": "signature not verified: TLS 1.3 staple read from openssl text output", **values}
            return result(CHECK_ID, status, message, observations, [f"certificate status: {values.get('certificate_status', 'n/a')}"])
        return result(CHECK_ID, INCONCLUSIVE, f"OCSP stapling could not be determined ({text_detail or detail}).", {"stapling": "unknown"})
    return result(CHECK_ID, INCONCLUSIVE, f"OCSP stapling could not be determined ({detail}).", {"stapling": "unknown"})


def _tls13_verdict(values: dict) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    if values.get("response_status", "").lower() != "successful":
        return FAIL, "The stapled OCSP response is not a successful response."
    next_update = _parse_openssl_time(values.get("next_update", ""))
    if next_update and next_update + CLOCK_SKEW < now:
        return FAIL, "The stapled OCSP response has expired."
    status = values.get("certificate_status", "").lower()
    if status == "revoked":
        return FAIL, "The server staples an OCSP response saying its certificate is revoked."
    if status != "good":
        return FAIL, f"The stapled OCSP response reports the status {status or 'unknown'}."
    return PASS, "The TLS 1.3 server staples a current OCSP response with the status good (signature not verified)."
