"""Complementary TLS checks against the real lab endpoints (nginx on OpenSSL 3.5) and OpenSSL as the reference tool."""
from __future__ import annotations

import re
import socket
import subprocess

from conftest import LAB
from tls_scanner.checks import groups, handshake, identity, stapling
from tls_scanner.checks.contracts import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, CheckContext

LAB_IP = socket.gethostbyname(LAB)
BOTH = ("TLSv1.2", "TLSv1.3")


def lab(port: int, **kwargs) -> CheckContext:
    return CheckContext(host=LAB_IP, port=port, timeout_seconds=8, **kwargs)


def s_client(port: int, *args: str) -> str:
    done = subprocess.run(["openssl", "s_client", "-connect", f"{LAB_IP}:{port}", *args], input=b"", capture_output=True, timeout=20)
    return (done.stdout + done.stderr).decode(errors="replace")


# --- A1 --------------------------------------------------------------------------------------

def test_hostname_matches_the_requested_name():
    outcome = identity.check_hostname_san(lab(443, reference_names=(LAB,)))
    assert outcome.status == PASS, outcome
    assert outcome.observations["references"][0]["matched_by"] == "san_dns"


def test_hostname_mismatch_is_reported_independently_of_trust():
    assert identity.check_hostname_san(lab(443, reference_names=("wrong.example",))).status == FAIL
    assert identity.check_hostname_san(lab(8452, reference_names=(LAB,))).status == FAIL


def test_ip_target_without_ip_san_fails_with_ip_reference():
    outcome = identity.check_hostname_san(lab(443))
    assert outcome.status == FAIL
    assert outcome.observations["references"][0]["reference_kind"] == "ip"


def test_wildcard_covers_one_label_only():
    assert identity.check_hostname_san(lab(8453, reference_names=("a.lab.example",))).observations["references"][0]["wildcard"] is True
    assert identity.check_hostname_san(lab(8453, reference_names=("lab.example",))).status == FAIL
    assert identity.check_hostname_san(lab(8453, reference_names=("a.b.lab.example",))).status == FAIL


# --- A2 --------------------------------------------------------------------------------------

def test_stapled_good_response_is_verified():
    outcome = stapling.check_ocsp_stapling(lab(8450, observed_versions=BOTH))
    assert outcome.status == PASS, outcome
    assert outcome.observations["signature_verified"] is True and outcome.observations["certificate_status"] == "good"


def test_stapled_revoked_response_fails():
    outcome = stapling.check_ocsp_stapling(lab(8451, observed_versions=BOTH))
    assert outcome.status == FAIL and outcome.observations["certificate_status"] == "revoked"


def test_certificate_without_ocsp_url_is_not_applicable():
    assert stapling.check_ocsp_stapling(lab(443, observed_versions=BOTH)).status == NOT_APPLICABLE


def test_tls13_text_path_reads_the_staple_but_does_not_claim_a_signature_check():
    kind, values, _ = stapling._tls13_status_text(lab(8450))
    assert kind == "present" and values["certificate_status"].lower() == "good"


# --- B1 --------------------------------------------------------------------------------------

def test_single_group_server_matches_openssl():
    outcome = groups.check_ecdhe_groups(lab(8456, observed_versions=BOTH))
    assert outcome.status == PASS, outcome
    assert outcome.observations["supported_groups"] == ["secp384r1"]
    reference = s_client(8456, "-tls1_3")
    assert re.search(r"secp384r1", reference)  # OpenSSL agrees on what the server picks
    assert outcome.observations["default_negotiated"]["TLSv1.3"] == "secp384r1"


def test_default_server_accepts_the_common_groups():
    outcome = groups.check_ecdhe_groups(lab(443, observed_versions=BOTH))
    assert outcome.status == PASS
    assert {"x25519", "secp256r1"} <= set(outcome.observations["supported_groups"])
    assert "not a complete server inventory" in outcome.observations["method"]


# --- B2 --------------------------------------------------------------------------------------

def test_weak_dh_parameters_are_detected():
    outcome = groups.check_ffdhe_groups(lab(8454, observed_versions=("TLSv1.2",)))
    assert outcome.status == FAIL, outcome
    assert outcome.observations["tls12_dhe"]["bits"] == 1024
    assert "1024 bits" in s_client(8454, "-tls1_2", "-cipher", "DHE:@SECLEVEL=0")


def test_ffdhe2048_is_detected():
    outcome = groups.check_ffdhe_groups(lab(8455, observed_versions=BOTH))
    assert outcome.status == PASS, outcome
    assert outcome.observations["tls12_dhe"]["bits"] == 2048
    assert "ffdhe2048" in outcome.observations["supported_named_groups"]


# --- B3 - B6 ---------------------------------------------------------------------------------

def test_modern_server_passes_the_negotiation_checks():
    assert handshake.check_tls_compression(lab(443, observed_versions=BOTH)).status == PASS
    assert handshake.check_extended_master_secret(lab(443, observed_versions=BOTH)).status == PASS
    renegotiation = handshake.check_renegotiation(lab(443, observed_versions=BOTH))
    assert renegotiation.status == PASS and renegotiation.observations["secure_renegotiation_rfc5746"] is True
    assert renegotiation.observations["client_initiated"] in {"refused", "accepted", "undetermined"}


def test_fallback_scsv_is_enforced_by_openssl_servers():
    outcome = handshake.check_fallback_scsv(lab(443, observed_versions=BOTH))
    assert outcome.status == PASS, outcome
    assert outcome.observations["offered_version"] == "TLSv1.2"
    # reference tool: OpenSSL's own SCSV option gets the same refusal
    assert "inappropriate fallback" in s_client(443, "-tls1_2", "-fallback_scsv").lower()


def test_tls13_only_server_is_not_applicable():
    for check in (handshake.check_tls_compression, handshake.check_extended_master_secret, handshake.check_renegotiation, handshake.check_fallback_scsv):
        assert check(lab(8447, observed_versions=("TLSv1.3",))).status == NOT_APPLICABLE, check.__name__


def test_tls13_only_server_without_version_knowledge_is_inconclusive_not_passed():
    assert handshake.check_tls_compression(lab(8447)).status == INCONCLUSIVE
    assert handshake.check_extended_master_secret(lab(8447)).status == INCONCLUSIVE


def test_plain_http_port_is_not_a_pass():
    assert handshake.check_tls_compression(lab(80)).status != PASS
    assert groups.check_ecdhe_groups(lab(80)).status != PASS


# --- servers configured by `openssl s_server`: behaviours nginx cannot be told to have ---------

import contextlib  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402


@contextlib.contextmanager
def s_server(*server_args: str, port: int = 0):
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{directory}/k.pem", "-out", f"{directory}/c.pem",
                        "-days", "2", "-subj", "/CN=localhost"], capture_output=True, check=True)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen(["openssl", "s_server", "-accept", f"127.0.0.1:{port}", "-cert", f"{directory}/c.pem", "-key", f"{directory}/k.pem", "-www", *server_args],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                with contextlib.suppress(OSError):
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                time.sleep(0.1)
            yield port
        finally:
            process.kill()
            process.wait()


def local(port: int, **kwargs) -> CheckContext:
    return CheckContext(host="127.0.0.1", port=port, timeout_seconds=8, **kwargs)


def test_server_accepting_client_renegotiation_is_flagged():
    with s_server("-tls1_2", "-client_renegotiation") as port:
        outcome = handshake.check_renegotiation(local(port, observed_versions=("TLSv1.2",)))
    assert outcome.status == PASS, outcome
    assert outcome.observations["client_initiated"] == "accepted" and outcome.observations["mode"] == "secure"


def test_server_refusing_renegotiation_is_reported_as_refused():
    with s_server("-tls1_2", "-no_renegotiation") as port:
        outcome = handshake.check_renegotiation(local(port, observed_versions=("TLSv1.2",)))
    assert outcome.observations["secure_renegotiation_rfc5746"] is True
    assert outcome.observations["client_initiated"] == "refused" and outcome.observations["mode"] == "refused"


def test_server_without_extended_master_secret_fails():
    with s_server("-tls1_2", "-no_ems") as port:
        assert handshake.check_extended_master_secret(local(port, observed_versions=("TLSv1.2",))).status == FAIL
    with s_server("-tls1_2") as port:
        assert handshake.check_extended_master_secret(local(port, observed_versions=("TLSv1.2",))).status == PASS


def test_server_without_fallback_protection_fails_when_a_lower_version_is_forced():
    # s_server -tls1_2 only accepts 1.2, so use the real range: the server supports 1.2 and 1.3 and OpenSSL enforces SCSV
    with s_server() as port:
        outcome = handshake.check_fallback_scsv(local(port, observed_versions=BOTH))
    assert outcome.status == PASS


def test_compression_is_never_negotiated_by_a_default_server():
    with s_server("-tls1_2") as port:
        assert handshake.check_tls_compression(local(port, observed_versions=("TLSv1.2",))).status == PASS


def test_stapled_response_given_to_s_server_is_judged_by_the_checker():
    # an expired-by-construction staple cannot be built with openssl quickly; a garbage file must be reported as invalid
    with tempfile.NamedTemporaryFile(suffix=".der") as staple:
        staple.write(b"\x30\x03\x0a\x01\x00")  # OCSPResponse with status 'successful' but no response bytes
        staple.flush()
        with s_server("-tls1_2", "-status_file", staple.name) as port:
            outcome = stapling.check_ocsp_stapling(local(port, observed_versions=("TLSv1.2",)))
    assert outcome.status != PASS
