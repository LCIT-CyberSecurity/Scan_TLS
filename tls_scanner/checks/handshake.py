"""
B3 TLS compression, B4 renegotiation, B5 TLS_FALLBACK_SCSV, B6 Extended Master Secret.

These are negotiation-level controls. Compression, EMS, secure-renegotiation advertisement and
fallback protection are read from the server's answer to a single raw ClientHello (see
`transport.send_client_hello`); only the client-initiated renegotiation test uses a completed
handshake. No compression, legacy renegotiation or other risky mechanism is ever enabled on the
client side, and no application data is sent.
"""

from __future__ import annotations

import re
import select
import shutil
import subprocess
import time

from .protocols import ADAPTERS, S_CLIENT_NAMES
from .contracts import FAIL, INCONCLUSIVE, NOT_APPLICABLE, NOT_TESTED, PASS, CheckContext, CheckResult, result
from .transport import (
    ALERT_INAPPROPRIATE_FALLBACK,
    ALERT_PROTOCOL_VERSION,
    DEFAULT_CIPHER_SUITES,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_RENEGOTIATION_INFO,
    SCSV_FALLBACK,
    TLS_VERSION_CODES,
    ServerReply,
    format_endpoint,
    max_observed_version,
    send_client_hello,
)
from ..pki import safe_sni_name

COMPRESSION_ID = "tls_compression"
RENEGOTIATION_ID = "renegotiation"
FALLBACK_ID = "fallback_scsv"
EMS_ID = "extended_master_secret"

LEGACY_VERSIONS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2")
VERSION_ORDER = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")


def _starttls_unsupported(check_id: str, context: CheckContext) -> CheckResult | None:
    if context.starttls and context.starttls not in ADAPTERS:
        return result(check_id, NOT_TESTED, f"STARTTLS {context.starttls} is not supported by this check")
    return None


def _no_legacy_versions(context: CheckContext) -> bool:
    """True when the main scan proved that the endpoint speaks TLS 1.3 only (no version <= 1.2)."""
    return bool(context.observed_versions) and not any(v in LEGACY_VERSIONS for v in context.observed_versions)


def _reply_summary(reply: ServerReply) -> str:
    if reply.kind == "server_hello":
        return f"ServerHello {reply.version}"
    if reply.kind == "alert":
        return f"alert {reply.alert}"
    return reply.error or reply.kind


def _unusable_reply(check_id: str, context: CheckContext, reply: ServerReply) -> CheckResult:
    """Answer to a probe that produced no ServerHello: protocol refusal or no answer."""
    observations = {"reply": _reply_summary(reply)}
    if reply.kind == "alert" and reply.alert == ALERT_PROTOCOL_VERSION and _no_legacy_versions(context):
        return result(check_id, NOT_APPLICABLE, "The endpoint only supports TLS 1.3, where this mechanism does not exist.", observations)
    return result(check_id, INCONCLUSIVE, f"The server did not answer the probe with a ServerHello ({_reply_summary(reply)}).", observations)


# --- B3 -----------------------------------------------------------------------------------------


def check_tls_compression(context: CheckContext) -> CheckResult:
    unsupported = _starttls_unsupported(COMPRESSION_ID, context)
    if unsupported:
        return unsupported
    if _no_legacy_versions(context):
        return result(COMPRESSION_ID, NOT_APPLICABLE, "TLS 1.3 removed compression; the endpoint only supports TLS 1.3.", {"observed_versions": list(context.observed_versions)})
    reply = send_client_hello(context, compression_methods=(1, 0))  # DEFLATE offered, then null
    if reply.kind != "server_hello":
        return _unusable_reply(COMPRESSION_ID, context, reply)
    observations = {"negotiated_version": reply.version, "compression_method": reply.compression, "offered": ["DEFLATE", "null"]}
    if reply.compression == 0:
        return result(COMPRESSION_ID, PASS, "The server did not select TLS compression although DEFLATE was offered.", observations, [f"ServerHello {reply.version}, compression method 0"])
    return result(COMPRESSION_ID, FAIL, "The server negotiated TLS compression (CRIME exposure).", observations, [f"ServerHello {reply.version}, compression method {reply.compression}"])


# --- B6 -----------------------------------------------------------------------------------------


def check_extended_master_secret(context: CheckContext) -> CheckResult:
    unsupported = _starttls_unsupported(EMS_ID, context)
    if unsupported:
        return unsupported
    if _no_legacy_versions(context):
        return result(EMS_ID, NOT_APPLICABLE, "Extended Master Secret applies to TLS 1.2 and earlier; the endpoint only supports TLS 1.3.", {"observed_versions": list(context.observed_versions)})
    reply = send_client_hello(context, extended_master_secret=True)
    if reply.kind != "server_hello":
        return _unusable_reply(EMS_ID, context, reply)
    observations = {"negotiated_version": reply.version, "extension_in_server_hello": reply.has_extension(EXT_EXTENDED_MASTER_SECRET)}
    if reply.version == "TLSv1.3":
        return result(EMS_ID, NOT_APPLICABLE, "TLS 1.3 was negotiated; Extended Master Secret does not apply.", observations)
    if reply.has_extension(EXT_EXTENDED_MASTER_SECRET):
        return result(EMS_ID, PASS, f"The server supports Extended Master Secret ({reply.version}).", observations, [f"ServerHello {reply.version} carries extension 23"])
    return result(EMS_ID, FAIL, f"The server did not echo Extended Master Secret ({reply.version}): sessions are exposed to triple-handshake style attacks.", observations, [f"ServerHello {reply.version} without extension 23"])


# --- B5 -----------------------------------------------------------------------------------------


def choose_fallback_version(observed_versions) -> tuple[str | None, str]:
    """Pick a supported version below the highest one that can be offered by a raw hello (TLS 1.0-1.2)."""
    supported = [v for v in VERSION_ORDER if v in set(observed_versions)]
    if len(supported) < 2:
        return None, "single_version"
    candidates = [v for v in supported[:-1] if v in TLS_VERSION_CODES]
    if not candidates:
        return None, "not_probeable"
    return candidates[-1], ""


def check_fallback_scsv(context: CheckContext) -> CheckResult:
    unsupported = _starttls_unsupported(FALLBACK_ID, context)
    if unsupported:
        return unsupported
    if not context.observed_versions:
        return result(FALLBACK_ID, NOT_TESTED, "The supported TLS versions were not established by the scan, so the preconditions cannot be checked.")
    offered, reason = choose_fallback_version(context.observed_versions)
    if offered is None:
        if reason == "single_version":
            return result(FALLBACK_ID, NOT_APPLICABLE, "The endpoint supports a single TLS version: there is no higher version to be downgraded from.", {"observed_versions": list(context.observed_versions)})
        return result(FALLBACK_ID, INCONCLUSIVE, "The only lower versions supported cannot be probed by this check.", {"observed_versions": list(context.observed_versions)})
    code = TLS_VERSION_CODES[offered]
    baseline = send_client_hello(context, max_version=code)
    if baseline.kind != "server_hello" or baseline.version != offered:
        return result(FALLBACK_ID, INCONCLUSIVE, f"The reference negotiation at {offered} did not succeed ({_reply_summary(baseline)}); no conclusion can be drawn.",
                      {"offered_version": offered, "reference": _reply_summary(baseline)})
    suites = (*DEFAULT_CIPHER_SUITES, SCSV_FALLBACK)
    probe = send_client_hello(context, max_version=code, cipher_suites=suites)
    observations = {"offered_version": offered, "highest_supported_version": max_observed_version(context.observed_versions), "reference": _reply_summary(baseline), "with_scsv": _reply_summary(probe)}
    if probe.kind == "alert" and probe.alert == ALERT_INAPPROPRIATE_FALLBACK:
        return result(FALLBACK_ID, PASS, f"The server rejects a {offered} connection carrying TLS_FALLBACK_SCSV (alert inappropriate_fallback).", observations, [f"reference {offered}: ServerHello", "with SCSV: alert 86"])
    if probe.kind == "server_hello" and probe.version == offered:
        return result(FALLBACK_ID, FAIL, f"The server accepts a downgraded {offered} connection although TLS_FALLBACK_SCSV signals a fallback.", observations, [f"reference {offered}: ServerHello", f"with SCSV: ServerHello {probe.version}"])
    return result(FALLBACK_ID, INCONCLUSIVE, f"Unexpected answer to the SCSV probe ({_reply_summary(probe)}).", observations)


# --- B4 -----------------------------------------------------------------------------------------


def client_initiated_renegotiation(context: CheckContext) -> tuple[str, str]:
    """One TLS 1.2 handshake, then one 'R' (renegotiate) command. Returns (outcome, detail).

    outcome: accepted | refused | undetermined. Nothing legacy is enabled: OpenSSL's default client
    already refuses servers without RFC 5746.
    """
    if shutil.which("openssl") is None:
        return "undetermined", "openssl is not available"
    command = ["openssl", "s_client", "-connect", format_endpoint(context.host, context.port), "-tls1_2", "-msg"]
    if context.starttls:
        command.extend(["-starttls", S_CLIENT_NAMES.get(context.starttls, context.starttls)])
    name = safe_sni_name(context.sni or "")
    if name:
        command.extend(["-servername", name])
    budget = context.probe_timeout()
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as error:
        return "undetermined", str(error)
    output = b""
    started = time.monotonic()
    sent = False
    try:
        while time.monotonic() - started < budget:
            ready, _, _ = select.select([process.stdout], [], [], 0.2)
            if ready:
                chunk = process.stdout.read1(65536) if hasattr(process.stdout, "read1") else b""
                if not chunk:
                    break
                output += chunk
                if len(output) > 524288:
                    break
            if not sent and (b"Cipher is" in output or time.monotonic() - started > budget / 3):
                try:
                    process.stdin.write(b"R\n")
                    process.stdin.flush()
                except OSError:
                    break
                sent = True
                renegotiation_started = time.monotonic()
            if sent and time.monotonic() - renegotiation_started > min(3.0, budget / 3):
                break
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass
        process.kill()
        process.wait()
    text = output.decode("utf-8", errors="replace")
    if "RENEGOTIATING" not in text:
        return "undetermined", "the client could not start a renegotiation"
    after = text.split("RENEGOTIATING", 1)[1]
    if re.search(r"no_renegotiation|fatal|handshake_failure|unexpected_message", after, re.IGNORECASE):
        return "refused", "alert received after the renegotiation request"
    if re.search(r"Handshake.*ServerHello", after) or "ServerHello" in after:
        return "accepted", "a second ServerHello was received"
    return "undetermined", "no decisive answer after the renegotiation request"


def check_renegotiation(context: CheckContext) -> CheckResult:
    unsupported = _starttls_unsupported(RENEGOTIATION_ID, context)
    if unsupported:
        return unsupported
    if _no_legacy_versions(context):
        return result(RENEGOTIATION_ID, NOT_APPLICABLE, "TLS 1.3 has no renegotiation; the endpoint only supports TLS 1.3.", {"mode": "not_applicable"})
    reply = send_client_hello(context, renegotiation_info=True)
    if reply.kind != "server_hello":
        return _unusable_reply(RENEGOTIATION_ID, context, reply)
    if reply.version == "TLSv1.3":
        return result(RENEGOTIATION_ID, NOT_APPLICABLE, "TLS 1.3 was negotiated.", {"mode": "not_applicable"})
    secure = reply.has_extension(EXT_RENEGOTIATION_INFO)
    observations = {"negotiated_version": reply.version, "secure_renegotiation_rfc5746": secure}
    if not secure:
        observations["mode"] = "insecure"
        return result(RENEGOTIATION_ID, FAIL, f"The server does not support secure renegotiation (RFC 5746) at {reply.version}.", observations, ["ServerHello without renegotiation_info"])
    outcome, detail = client_initiated_renegotiation(context) if context.can_probe() else ("undetermined", "no time left")
    observations["client_initiated"] = outcome
    evidence = ["ServerHello carries renegotiation_info", f"client-initiated renegotiation: {outcome} ({detail})"]
    if outcome == "refused":
        observations["mode"] = "refused"
        return result(RENEGOTIATION_ID, PASS, "Secure renegotiation is supported and client-initiated renegotiation is refused.", observations, evidence)
    if outcome == "accepted":
        observations["mode"] = "secure"
        return result(RENEGOTIATION_ID, PASS, "Secure renegotiation (RFC 5746) is supported; the server accepts client-initiated renegotiation, which can be abused for resource exhaustion.", observations, evidence)
    observations["mode"] = "secure"
    return result(RENEGOTIATION_ID, PASS, "Secure renegotiation (RFC 5746) is supported; client-initiated renegotiation could not be determined.", observations, evidence)
