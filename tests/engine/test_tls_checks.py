"""Unit tests of the complementary TLS checks (tls_scanner.checks). No network beyond loopback sockets.

Run: python -m unittest discover tests/engine   (or pytest tests/engine)
"""

import datetime
import socket
import struct
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tls_scanner.checks import catalog, contracts, groups, handshake, identity, stapling, transport
from tls_scanner.checks.contracts import (
    ERROR, FAIL, INCONCLUSIVE, NOT_APPLICABLE, NOT_TESTED, PASS, CheckContext, CheckResult, result, run_check,
)
from tls_scanner.checks.transport import (
    ALERT_INAPPROPRIATE_FALLBACK, ALERT_PROTOCOL_VERSION, EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO, ServerReply, SClientOutput,
)
from tls_scanner.models import ConfigError


def ctx(**kwargs):
    base = dict(host="192.0.2.10", port=443, timeout_seconds=2)
    base.update(kwargs)
    return CheckContext(**base)


# ---------------------------------------------------------------------------------------------
# contract
# ---------------------------------------------------------------------------------------------


class ContractTests(unittest.TestCase):
    def test_exception_becomes_error_result(self):
        def boom(_):
            raise RuntimeError("kaput")

        outcome = run_check("x", boom, ctx())
        self.assertEqual(outcome.status, ERROR)
        self.assertIn("kaput", outcome.message)
        self.assertEqual(outcome.check_id, "x")

    def test_cancelled_scan_gives_not_tested_without_calling_the_check(self):
        event = threading.Event()
        event.set()
        called = []
        outcome = run_check("x", lambda c: called.append(1), ctx(cancel_event=event))
        self.assertEqual(outcome.status, NOT_TESTED)
        self.assertFalse(called)

    def test_exhausted_budget_gives_not_tested(self):
        outcome = run_check("x", lambda c: result("x", PASS), ctx(deadline=time.monotonic() - 1))
        self.assertEqual(outcome.status, NOT_TESTED)

    def test_unknown_status_is_an_error_and_duration_is_recorded(self):
        outcome = run_check("x", lambda c: CheckResult("x", "GREAT"), ctx())
        self.assertEqual(outcome.status, ERROR)
        ok = run_check("x", lambda c: result("x", PASS), ctx())
        self.assertGreaterEqual(ok.duration_ms, 0)

    def test_evidence_is_bounded_and_single_line(self):
        evidence = contracts.bounded_evidence(["a\nb  c"] + ["x" * 1000] + [f"e{i}" for i in range(50)])
        self.assertEqual(evidence[0], "a b c")
        self.assertLessEqual(len(evidence), contracts.MAX_EVIDENCE_ITEMS)
        self.assertTrue(all(len(item) <= contracts.MAX_EVIDENCE_CHARS for item in evidence))

    def test_probe_timeout_never_exceeds_the_remaining_budget(self):
        self.assertLessEqual(ctx(timeout_seconds=30, deadline=time.monotonic() + 3).probe_timeout(), 3.0)
        self.assertFalse(ctx(deadline=time.monotonic() - 1).can_probe())


# ---------------------------------------------------------------------------------------------
# helpers to build certificates
# ---------------------------------------------------------------------------------------------


def make_certificate(sans=(), cn="lab", ips=(), issuer=None, issuer_key=None, serial=None, aia_ocsp=None, must_staple=False, ocsp_signing=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_name = issuer.subject if issuer is not None else subject
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).public_key(key.public_key())
        .serial_number(serial or x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
    )
    names = [x509.DNSName(name) for name in sans] + [x509.IPAddress(__import__("ipaddress").ip_address(ip)) for ip in ips]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if aia_ocsp:
        builder = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(x509.AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(aia_ocsp))]), critical=False)
    if must_staple:
        builder = builder.add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False)
    if ocsp_signing:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
    signer = issuer_key or key
    return builder.sign(signer, hashes.SHA256()), key


# ---------------------------------------------------------------------------------------------
# A1 - identity
# ---------------------------------------------------------------------------------------------


class DnsMatchingTests(unittest.TestCase):
    def test_exact_and_case_insensitive(self):
        self.assertTrue(identity.dns_name_matches("www.Example.org", "WWW.example.ORG."))
        self.assertFalse(identity.dns_name_matches("www.example.org", "example.org"))

    def test_wildcard_covers_exactly_one_label(self):
        self.assertTrue(identity.dns_name_matches("*.example.org", "www.example.org"))
        self.assertFalse(identity.dns_name_matches("*.example.org", "example.org"))
        self.assertFalse(identity.dns_name_matches("*.example.org", "a.b.example.org"))

    def test_unsafe_wildcards_never_match(self):
        for pattern in ("*.com", "w*.example.org", "*w.example.org", "www.*.org", "*.*.example.org", "*"):
            with self.subTest(pattern=pattern):
                self.assertFalse(identity.dns_name_matches(pattern, "www.example.org"))

    def test_internationalised_names_compare_as_a_labels(self):
        self.assertTrue(identity.dns_name_matches("xn--bcher-kva.example", "bücher.example"))
        self.assertTrue(identity.dns_name_matches("bücher.example", "xn--bcher-kva.example"))
        self.assertFalse(identity.dns_name_matches("xn--bcher-kva.example", "buecher.example"))

    def test_invalid_names_do_not_match(self):
        self.assertFalse(identity.dns_name_matches("", "a.example"))
        self.assertFalse(identity.dns_name_matches("a.example", ""))


class IdentityMatchTests(unittest.TestCase):
    def setUp(self):
        certificate, _ = make_certificate(sans=["www.example.org", "*.api.example.org"], ips=["192.0.2.7", "2001:db8::7"], cn="legacy-cn.example")
        self.identities = identity.certificate_identities(certificate)

    def test_dns_reference_matches_san_dns(self):
        outcome = identity.match_identity("www.example.org", self.identities)
        self.assertTrue(outcome["matched"])
        self.assertEqual(outcome["matched_by"], "san_dns")

    def test_wildcard_flag(self):
        outcome = identity.match_identity("x.api.example.org", self.identities)
        self.assertTrue(outcome["matched"] and outcome["wildcard"])

    def test_ip_reference_uses_san_ip_only(self):
        self.assertEqual(identity.match_identity("192.0.2.7", self.identities)["matched_by"], "san_ip")
        self.assertTrue(identity.match_identity("2001:db8:0:0:0:0:0:7", self.identities)["matched"])
        self.assertFalse(identity.match_identity("192.0.2.8", self.identities)["matched"])

    def test_common_name_is_never_used(self):
        self.assertFalse(identity.match_identity("legacy-cn.example", self.identities)["matched"])

    def test_dns_name_does_not_match_an_ip_san_and_vice_versa(self):
        certificate, _ = make_certificate(sans=["192.0.2.7"])  # a DNS entry that merely looks like an IP
        self.assertFalse(identity.match_identity("192.0.2.7", identity.certificate_identities(certificate))["matched"])

    def test_certificate_without_san_is_flagged_cn_only(self):
        certificate, _ = make_certificate(sans=[], cn="old.example")
        outcome = identity.match_identity("old.example", identity.certificate_identities(certificate))
        self.assertFalse(outcome["matched"])
        self.assertTrue(outcome.get("cn_only"))


class HostnameCheckTests(unittest.TestCase):
    def chain_for(self, certificate):
        from tls_scanner.pki import PeerCertificateChain

        return PeerCertificateChain((certificate,))

    def test_no_reference_identity_is_not_tested(self):
        outcome = identity.check_hostname_san(ctx(host=""))
        self.assertEqual(outcome.status, NOT_TESTED)

    def test_requested_name_is_the_reference_never_a_ptr(self):
        certificate, _ = make_certificate(sans=["requested.example"])
        seen = []

        def fake_chain(host, port, fqdn, timeout):
            seen.append(fqdn)
            return self.chain_for(certificate)

        with patch.object(identity, "collect_peer_certificate_chain", fake_chain):
            outcome = identity.check_hostname_san(ctx(reference_names=("requested.example",), sni="ptr-name.invalid"))
        self.assertEqual(outcome.status, PASS)
        self.assertEqual(seen, ["requested.example"])  # SNI is the requested name, not the PTR

    def test_mismatch_fails_with_an_explicit_message(self):
        certificate, _ = make_certificate(sans=["other.example"])
        with patch.object(identity, "collect_peer_certificate_chain", lambda *a: self.chain_for(certificate)):
            outcome = identity.check_hostname_san(ctx(reference_names=("requested.example",)))
        self.assertEqual(outcome.status, FAIL)
        self.assertIn("independent of chain trust", outcome.message)

    def test_ip_target_checks_the_ip_san_without_sni(self):
        certificate, _ = make_certificate(sans=["host.example"], ips=["192.0.2.10"])
        seen = []

        def fake_chain(host, port, fqdn, timeout):
            seen.append(fqdn)
            return self.chain_for(certificate)

        with patch.object(identity, "collect_peer_certificate_chain", fake_chain):
            outcome = identity.check_hostname_san(ctx())
        self.assertEqual(outcome.status, PASS)
        self.assertEqual(seen, [""])
        self.assertEqual(outcome.observations["references"][0]["reference_kind"], "ip")

    def test_unreachable_certificate_is_inconclusive_not_failed(self):
        from tls_scanner.pki import PeerCertificateChain

        with patch.object(identity, "collect_peer_certificate_chain", lambda *a: PeerCertificateChain((), "error", "boom")):
            outcome = identity.check_hostname_san(ctx(reference_names=("a.example",)))
        self.assertEqual(outcome.status, INCONCLUSIVE)

    def test_several_names_one_failing_fails(self):
        certificate, _ = make_certificate(sans=["a.example"])
        with patch.object(identity, "collect_peer_certificate_chain", lambda *a: self.chain_for(certificate)):
            outcome = identity.check_hostname_san(ctx(reference_names=("a.example", "b.example")))
        self.assertEqual(outcome.status, FAIL)
        self.assertEqual([item["status"] for item in outcome.observations["references"]], [PASS, FAIL])

    def test_resolve_requested_names_skips_addresses_and_networks(self):
        self.assertEqual(identity.resolve_requested_names("192.0.2.1 10.0.0.0/24 2001:db8::1"), {})
        with patch.object(identity.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.5", 0))]):
            self.assertEqual(identity.resolve_requested_names("web.example."), {"192.0.2.5": ("web.example",)})
        with patch.object(identity.socket, "getaddrinfo", side_effect=socket.gaierror):
            self.assertEqual(identity.resolve_requested_names("gone.example"), {})


# ---------------------------------------------------------------------------------------------
# A2 - OCSP stapling
# ---------------------------------------------------------------------------------------------


def make_pki():
    ca_cert, ca_key = make_certificate(cn="Lab CA")
    leaf, leaf_key = make_certificate(sans=["lab"], issuer=ca_cert, issuer_key=ca_key, serial=4097, aia_ocsp="http://ocsp.invalid/")
    return ca_cert, ca_key, leaf


def make_ocsp(leaf, ca_cert, signer_cert, signer_key, status=ocsp.OCSPCertStatus.GOOD, this_update=None, next_update=None, responder_certs=()):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=leaf, issuer=ca_cert, algorithm=hashes.SHA1(), cert_status=status,
        this_update=this_update or now - datetime.timedelta(hours=1), next_update=next_update or now + datetime.timedelta(days=2),
        revocation_time=now - datetime.timedelta(days=1) if status == ocsp.OCSPCertStatus.REVOKED else None, revocation_reason=None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, signer_cert)
    for cert in responder_certs:
        builder = builder.certificates([cert])
    return builder.sign(signer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


class StaplingEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.ca, self.ca_key, self.leaf = make_pki()

    def evaluate(self, der, issuer="ca"):
        return stapling.evaluate_staple(der, self.leaf, self.ca if issuer == "ca" else None)

    def test_good_current_signed_response_passes(self):
        status, message, observations = self.evaluate(make_ocsp(self.leaf, self.ca, self.ca, self.ca_key))
        self.assertEqual(status, PASS, message)
        self.assertTrue(observations["signature_verified"])
        self.assertEqual(observations["certificate_status"], "good")

    def test_revoked_response_fails(self):
        status, _, observations = self.evaluate(make_ocsp(self.leaf, self.ca, self.ca, self.ca_key, status=ocsp.OCSPCertStatus.REVOKED))
        self.assertEqual(status, FAIL)
        self.assertEqual(observations["certificate_status"], "revoked")

    def test_unknown_status_fails(self):
        status, _, _ = self.evaluate(make_ocsp(self.leaf, self.ca, self.ca, self.ca_key, status=ocsp.OCSPCertStatus.UNKNOWN))
        self.assertEqual(status, FAIL)

    def test_expired_response_fails(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        der = make_ocsp(self.leaf, self.ca, self.ca, self.ca_key, this_update=now - datetime.timedelta(days=9), next_update=now - datetime.timedelta(days=2))
        status, _, observations = self.evaluate(der)
        self.assertEqual(status, FAIL)
        self.assertEqual(observations["reason"], "expired")

    def test_future_response_fails(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        der = make_ocsp(self.leaf, self.ca, self.ca, self.ca_key, this_update=now + datetime.timedelta(hours=3), next_update=now + datetime.timedelta(days=3))
        self.assertEqual(self.evaluate(der)[0], FAIL)

    def test_response_for_another_certificate_fails(self):
        other, _ = make_certificate(sans=["other"], issuer=self.ca, issuer_key=self.ca_key, serial=9999)
        der = make_ocsp(other, self.ca, self.ca, self.ca_key)
        status, _, observations = self.evaluate(der)
        self.assertEqual(status, FAIL)
        self.assertEqual(observations["reason"], "serial_mismatch")

    def test_signature_by_a_stranger_fails(self):
        stranger, stranger_key = make_certificate(cn="Stranger")
        der = make_ocsp(self.leaf, self.ca, stranger, stranger_key)
        status, _, observations = self.evaluate(der)
        self.assertEqual(status, FAIL)
        self.assertEqual(observations["reason"], "bad_signature")

    def test_delegated_responder_signed_by_the_issuer_passes(self):
        responder, responder_key = make_certificate(cn="Delegated", issuer=self.ca, issuer_key=self.ca_key, ocsp_signing=True)
        der = make_ocsp(self.leaf, self.ca, responder, responder_key, responder_certs=[responder])
        self.assertEqual(self.evaluate(der)[0], PASS)

    def test_missing_issuer_is_inconclusive(self):
        status, message, observations = self.evaluate(make_ocsp(self.leaf, self.ca, self.ca, self.ca_key), issuer=None)
        self.assertEqual(status, INCONCLUSIVE)
        self.assertFalse(observations["signature_verified"])

    def test_garbage_fails_as_invalid(self):
        status, _, observations = self.evaluate(b"\x30\x03garbage")
        self.assertEqual(status, FAIL)
        self.assertEqual(observations["response"], "invalid")

    def test_malformed_status_response_fails(self):
        der = ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.TRY_LATER).public_bytes(serialization.Encoding.DER)
        self.assertEqual(self.evaluate(der)[0], FAIL)


class StaplingMessageTests(unittest.TestCase):
    def test_certificate_message_round_trip(self):
        first, _ = make_certificate(sans=["a"])
        second, _ = make_certificate(sans=["b"])
        entries = b"".join(len(der).to_bytes(3, "big") + der for der in (c.public_bytes(serialization.Encoding.DER) for c in (first, second)))
        parsed = stapling.parse_certificate_message(len(entries).to_bytes(3, "big") + entries)
        self.assertEqual([c.serial_number for c in parsed], [first.serial_number, second.serial_number])
        self.assertEqual(stapling.parse_certificate_message(b"\x00\x00"), [])

    def test_certificate_status_message(self):
        self.assertEqual(stapling.staple_from_status_message(b"\x01\x00\x00\x03abc"), b"abc")
        self.assertIsNone(stapling.staple_from_status_message(b"\x02\x00\x00\x01a"))
        self.assertIsNone(stapling.staple_from_status_message(b"\x01"))


class StaplingCheckTests(unittest.TestCase):
    def setUp(self):
        self.ca, self.ca_key, self.leaf = make_pki()

    def test_no_ocsp_url_and_no_staple_is_not_applicable(self):
        bare, _ = make_certificate(sans=["lab"])
        with patch.object(stapling, "_raw_tls12_staple", lambda c: ("absent", [bare], None, "")), patch.object(stapling.time, "sleep", lambda s: None):
            outcome = stapling.check_ocsp_stapling(ctx())
        self.assertEqual(outcome.status, NOT_APPLICABLE)

    def test_absent_staple_fails_after_two_attempts(self):
        calls = []

        def fake(c):
            calls.append(1)
            return "absent", [self.leaf, self.ca], None, ""

        with patch.object(stapling, "_raw_tls12_staple", fake), patch.object(stapling.time, "sleep", lambda s: None):
            outcome = stapling.check_ocsp_stapling(ctx())
        self.assertEqual(outcome.status, FAIL)
        self.assertEqual(len(calls), 2)
        self.assertEqual(outcome.observations["stapling"], "absent")

    def test_valid_staple_passes(self):
        der = make_ocsp(self.leaf, self.ca, self.ca, self.ca_key)
        with patch.object(stapling, "_raw_tls12_staple", lambda c: ("present", [self.leaf, self.ca], der, "")):
            outcome = stapling.check_ocsp_stapling(ctx())
        self.assertEqual(outcome.status, PASS)

    def test_tls13_only_server_uses_openssl_text_and_states_the_limit(self):
        text = "OCSP Response Status: successful (0x0)\nCert Status: good\nThis Update: Jan  1 00:00:00 2026 GMT\nNext Update: Jan  1 00:00:00 2099 GMT\nOCSP Response Data:"
        output = SClientOutput(text + "\nCipher is TLS_AES_256_GCM_SHA384\n", 0)
        with patch.object(stapling, "_raw_tls12_staple", lambda c: ("no_tls12", [], None, f"alert {ALERT_PROTOCOL_VERSION}")), \
                patch.object(stapling, "run_s_client", lambda *a, **k: output):
            outcome = stapling.check_ocsp_stapling(ctx(observed_versions=("TLSv1.3",)))
        self.assertEqual(outcome.status, PASS)
        self.assertFalse(outcome.observations["signature_verified"])
        self.assertIn("not verified", outcome.message)

    def test_tls13_revoked_text_fails(self):
        output = SClientOutput("OCSP Response Status: successful (0x0)\nCert Status: revoked\nOCSP Response Data:\nCipher is TLS_AES_256_GCM_SHA384\n", 0)
        with patch.object(stapling, "_raw_tls12_staple", lambda c: ("no_tls12", [], None, "alert 70")), patch.object(stapling, "run_s_client", lambda *a, **k: output):
            self.assertEqual(stapling.check_ocsp_stapling(ctx(observed_versions=("TLSv1.3",))).status, FAIL)

    def test_unreachable_is_inconclusive(self):
        with patch.object(stapling, "_raw_tls12_staple", lambda c: ("error", [], None, "timeout")):
            self.assertEqual(stapling.check_ocsp_stapling(ctx()).status, INCONCLUSIVE)

    def test_unsupported_starttls_is_not_tested(self):
        with patch.object(CheckContext, "starttls", "irc"):
            self.assertEqual(stapling.check_ocsp_stapling(ctx()).status, NOT_TESTED)


# ---------------------------------------------------------------------------------------------
# B1 / B2 - groups
# ---------------------------------------------------------------------------------------------

TLS13_X25519 = "Protocol  : TLSv1.3\nNegotiated TLS1.3 group: X25519\nCipher is TLS_AES_256_GCM_SHA384\n"
TLS12_P256 = "Protocol  : TLSv1.2\nServer Temp Key: ECDH, prime256v1, 256 bits\nCipher    : ECDHE-RSA-AES128-GCM-SHA256\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256\n"
TLS12_DH = "Protocol  : TLSv1.2\nServer Temp Key: DH, 1024 bits\nNew, TLSv1.2, Cipher is DHE-RSA-AES128-GCM-SHA256\n"


class KeyExchangeParsingTests(unittest.TestCase):
    def test_tls13_group(self):
        self.assertEqual(groups.parse_key_exchange(TLS13_X25519), {"group": "x25519", "family": "ecdhe", "bits": None})

    def test_tls12_ecdh_curve_is_canonicalised(self):
        self.assertEqual(groups.parse_key_exchange(TLS12_P256), {"group": "secp256r1", "family": "ecdhe", "bits": 256})

    def test_x25519_temp_key(self):
        self.assertEqual(groups.parse_key_exchange("Server Temp Key: X25519, 253 bits\n")["group"], "x25519")

    def test_dh_bits_and_ffdhe_group(self):
        self.assertEqual(groups.parse_key_exchange(TLS12_DH), {"group": None, "family": "dhe", "bits": 1024})
        parsed = groups.parse_key_exchange("Negotiated TLS1.3 group: ffdhe3072\n")
        self.assertEqual((parsed["family"], parsed["group"]), ("dhe", "ffdhe3072"))

    def test_openssl_35_peer_temp_key_lines(self):
        self.assertEqual(groups.parse_key_exchange("Peer Temp Key: ECDH, secp384r1, 384 bits\n")["group"], "secp384r1")
        self.assertEqual(groups.parse_key_exchange("Peer Temp Key: X25519, 253 bits\n")["group"], "x25519")
        self.assertTrue(groups._ffdhe_proven({"group": None, "family": "dhe", "bits": 3072}, "ffdhe3072"))
        self.assertFalse(groups._ffdhe_proven({"group": None, "family": "dhe", "bits": 2048}, "ffdhe3072"))
        self.assertFalse(groups._ffdhe_proven({"group": "x25519", "family": "ecdhe", "bits": 253}, "ffdhe2048"))

    def test_nothing_proven_without_key_exchange_lines(self):
        self.assertEqual(groups.parse_key_exchange("Cipher is AES128-SHA\n"), {"group": None, "family": None, "bits": None})


def fake_s_client(table):
    """table: function(args) -> SClientOutput-like (text, connected)."""

    def run(context, extra_args, **kwargs):
        text = table(list(extra_args))
        return SClientOutput(text, 0 if text else 1)

    return run


class EcdheGroupsTests(unittest.TestCase):
    def accepting(self, accepted):
        def table(args):
            version = "TLSv1.3" if "-tls1_3" in args else "TLSv1.2"
            group = args[args.index("-groups") + 1] if "-groups" in args else None
            chosen = group if group else accepted[0]
            if chosen not in accepted:
                return "error:0A000410:SSL routines::ssl/tls alert handshake failure\n"
            if version == "TLSv1.3":
                return f"Negotiated TLS1.3 group: {chosen}\nCipher is TLS_AES_256_GCM_SHA384\n"
            return f"Server Temp Key: ECDH, {chosen}, 256 bits\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256\n"

        return table

    def test_proven_groups_are_listed_per_version_and_not_called_complete(self):
        with patch.object(groups, "run_s_client", fake_s_client(self.accepting(["x25519", "secp384r1"]))):
            outcome = groups.check_ecdhe_groups(ctx(observed_versions=("TLSv1.2", "TLSv1.3")))
        self.assertEqual(outcome.status, PASS)
        self.assertEqual(outcome.observations["supported_groups"], ["secp384r1", "x25519"])
        self.assertIn("secp521r1", outcome.observations["by_version"]["TLSv1.3"]["not_accepted"])
        self.assertIn("not a complete server inventory", outcome.observations["method"])
        self.assertEqual(outcome.observations["default_negotiated"]["TLSv1.3"], "x25519")

    def test_handshake_without_ecdhe_proof_is_not_counted(self):
        def table(args):
            return "Cipher is AES128-SHA\nNew, TLSv1.2, Cipher is AES128-SHA\n"  # RSA key exchange only

        with patch.object(groups, "run_s_client", fake_s_client(table)):
            outcome = groups.check_ecdhe_groups(ctx(observed_versions=("TLSv1.2",)))
        self.assertNotEqual(outcome.status, PASS)
        self.assertEqual(outcome.observations["supported_groups"], [])

    def test_unreachable_probes_are_inconclusive_not_failed(self):
        with patch.object(groups, "run_s_client", lambda *a, **k: SClientOutput("", None, timed_out=True, error="timeout")):
            self.assertEqual(groups.check_ecdhe_groups(ctx(observed_versions=("TLSv1.2",))).status, INCONCLUSIVE)

    def test_endpoint_without_tls12_or_tls13_is_not_applicable(self):
        self.assertEqual(groups.check_ecdhe_groups(ctx(observed_versions=("TLSv1.0",))).status, NOT_APPLICABLE)

    def test_budget_exhaustion_leaves_groups_undetermined(self):
        with patch.object(groups, "run_s_client", fake_s_client(self.accepting(["x25519"]))):
            outcome = groups.check_ecdhe_groups(ctx(observed_versions=("TLSv1.3",), deadline=time.monotonic() + 0.4))
        self.assertTrue(outcome.observations["by_version"]["TLSv1.3"]["undetermined"])


class FfdheTests(unittest.TestCase):
    def test_weak_dh_parameters_fail(self):
        def table(args):
            return TLS12_DH if "-tls1_2" in args else "handshake failure\n"

        with patch.object(groups, "run_s_client", fake_s_client(table)):
            outcome = groups.check_ffdhe_groups(ctx(observed_versions=("TLSv1.2",)))
        self.assertEqual(outcome.status, FAIL)
        self.assertEqual(outcome.observations["tls12_dhe"]["bits"], 1024)

    def test_strong_dh_and_named_group_pass(self):
        def table(args):
            if "-tls1_3" in args:
                group = args[args.index("-groups") + 1]
                # OpenSSL 3.5 does not name the TLS 1.3 FFDHE group: only the DH size is printed
                return "Peer Temp Key: DH, 2048 bits\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n" if group == "ffdhe2048" else "handshake failure\n"
            return "Server Temp Key: DH, 2048 bits\nNew, TLSv1.2, Cipher is DHE-RSA-AES128-GCM-SHA256\n"

        with patch.object(groups, "run_s_client", fake_s_client(table)):
            outcome = groups.check_ffdhe_groups(ctx(observed_versions=("TLSv1.2", "TLSv1.3")))
        self.assertEqual(outcome.status, PASS)
        self.assertEqual(outcome.observations["supported_named_groups"], ["ffdhe2048"])

    def test_refusal_does_not_prove_absence_when_probes_fail_to_complete(self):
        with patch.object(groups, "run_s_client", lambda *a, **k: SClientOutput("", None, timed_out=True, error="timeout")):
            self.assertEqual(groups.check_ffdhe_groups(ctx(observed_versions=("TLSv1.2", "TLSv1.3"))).status, INCONCLUSIVE)

    def test_clean_refusal_everywhere_is_not_applicable(self):
        with patch.object(groups, "run_s_client", fake_s_client(lambda args: "sslv3 alert handshake failure\n")):
            outcome = groups.check_ffdhe_groups(ctx(observed_versions=("TLSv1.2", "TLSv1.3")))
        self.assertEqual(outcome.status, NOT_APPLICABLE)
        self.assertIn("not a proof", outcome.observations["tls12_dhe"]["note"])

    def test_tls13_only_endpoint_skips_the_tls12_probe(self):
        with patch.object(groups, "run_s_client", fake_s_client(lambda args: "handshake failure\n")):
            outcome = groups.check_ffdhe_groups(ctx(observed_versions=("TLSv1.3",)))
        self.assertIsNone(outcome.observations["tls12_dhe"]["negotiated"])


class FailureClassificationTests(unittest.TestCase):
    def test_refusal_versus_unreachable(self):
        self.assertEqual(transport.classify_s_client_failure(SClientOutput("tlsv1 alert protocol version", 1)), "refused")
        self.assertEqual(transport.classify_s_client_failure(SClientOutput("connect:errno=111 Connection refused", 1)), "unreachable")
        self.assertEqual(transport.classify_s_client_failure(SClientOutput("", None, timed_out=True)), "unreachable")
        self.assertEqual(transport.classify_s_client_failure(SClientOutput("something odd", 1)), "unreachable")

    def test_connected_requires_a_real_cipher(self):
        self.assertTrue(SClientOutput("New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256", 0).connected)
        self.assertFalse(SClientOutput("New, (NONE), Cipher is (NONE)", 1).connected)


# ---------------------------------------------------------------------------------------------
# raw ClientHello transport against a scripted server
# ---------------------------------------------------------------------------------------------


def server_hello(version=0x0303, cipher=0xC02F, compression=0, extensions=()):
    body = struct.pack("!H", version) + b"\x11" * 32 + b"\x00" + struct.pack("!H", cipher) + bytes([compression])
    ext = b"".join(struct.pack("!HH", code, len(data)) + data for code, data in extensions)
    body += struct.pack("!H", len(ext)) + ext
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    done = b"\x0e\x00\x00\x00"
    payload = message + done
    return b"\x16" + struct.pack("!HH", 0x0303, len(payload)) + payload


def alert(code, level=2):
    return b"\x15\x03\x03\x00\x02" + bytes([level, code])


class ScriptedServer:
    """Accepts connections on loopback; `responder(hello_bytes) -> bytes` builds the answer. Optional SMTP prelude."""

    def __init__(self, responder, smtp=False, delay=0.0):
        self.responder, self.smtp, self.delay = responder, smtp, delay
        self.hellos = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.stop = False
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        self.listener.settimeout(0.2)
        while not self.stop:
            try:
                connection, _ = self.listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self.handle, args=(connection,), daemon=True).start()

    def handle(self, connection):
        try:
            connection.settimeout(3)
            if self.smtp:
                connection.sendall(b"220 scripted ESMTP\r\n")
                connection.recv(1024)
                connection.sendall(b"250-scripted\r\n250 STARTTLS\r\n")
                connection.recv(1024)
                connection.sendall(b"220 go ahead\r\n")
            data = connection.recv(65536)
            self.hellos.append(data)
            time.sleep(self.delay)
            answer = self.responder(data)
            if answer:
                connection.sendall(answer)
            connection.close()
        except OSError:
            pass

    def close(self):
        self.stop = True
        self.listener.close()


def hello_version(data):
    return struct.unpack("!H", data[9:11])[0]


def hello_ciphers(data):
    position = 9 + 2 + 32
    position += 1 + data[position]
    length = struct.unpack("!H", data[position:position + 2])[0]
    return [struct.unpack("!H", data[position + 2 + i:position + 4 + i])[0] for i in range(0, length, 2)]


def hello_compressions(data):
    position = 9 + 2 + 32
    position += 1 + data[position]
    position += 2 + struct.unpack("!H", data[position:position + 2])[0]
    return list(data[position + 1:position + 1 + data[position]])


def hello_extension_codes(data):
    position = 9 + 2 + 32
    position += 1 + data[position]
    position += 2 + struct.unpack("!H", data[position:position + 2])[0]
    position += 1 + data[position]
    total = struct.unpack("!H", data[position:position + 2])[0]
    position += 2
    codes, end = [], position + total
    while position + 4 <= end:
        code, length = struct.unpack("!HH", data[position:position + 4])
        codes.append(code)
        position += 4 + length
    return codes


class RawTransportTests(unittest.TestCase):
    def test_server_hello_is_parsed_including_extensions(self):
        server = ScriptedServer(lambda hello: server_hello(extensions=[(EXT_EXTENDED_MASTER_SECRET, b""), (EXT_RENEGOTIATION_INFO, b"\x00")]))
        self.addCleanup(server.close)
        reply = transport.send_client_hello(ctx(host="127.0.0.1", port=server.port), extended_master_secret=True)
        self.assertEqual(reply.kind, "server_hello")
        self.assertEqual((reply.version, reply.cipher_suite, reply.compression), ("TLSv1.2", 0xC02F, 0))
        self.assertTrue(reply.has_extension(EXT_EXTENDED_MASTER_SECRET) and reply.has_extension(EXT_RENEGOTIATION_INFO))
        self.assertIn(EXT_EXTENDED_MASTER_SECRET, hello_extension_codes(server.hellos[0]))

    def test_alert_is_reported_with_its_description(self):
        server = ScriptedServer(lambda hello: alert(ALERT_PROTOCOL_VERSION))
        self.addCleanup(server.close)
        reply = transport.send_client_hello(ctx(host="127.0.0.1", port=server.port))
        self.assertEqual((reply.kind, reply.alert), ("alert", ALERT_PROTOCOL_VERSION))

    def test_silence_times_out_without_raising(self):
        server = ScriptedServer(lambda hello: b"", delay=0)
        self.addCleanup(server.close)
        started = time.monotonic()
        reply = transport.send_client_hello(ctx(host="127.0.0.1", port=server.port, timeout_seconds=1))
        self.assertNotEqual(reply.kind, "server_hello")
        self.assertLess(time.monotonic() - started, 3)

    def test_connection_refused_is_an_error_reply(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        self.assertEqual(transport.send_client_hello(ctx(host="127.0.0.1", port=port)).kind, "error")

    def test_garbage_answer_is_not_a_server_hello(self):
        server = ScriptedServer(lambda hello: b"HTTP/1.1 400 Bad Request\r\n\r\n")
        self.addCleanup(server.close)
        self.assertNotEqual(transport.send_client_hello(ctx(host="127.0.0.1", port=server.port)).kind, "server_hello")

    def test_smtp_starttls_prelude(self):
        server = ScriptedServer(lambda hello: server_hello(), smtp=True)
        self.addCleanup(server.close)
        with patch.object(CheckContext, "starttls", "smtp"):
            reply = transport.send_client_hello(ctx(host="127.0.0.1", port=server.port))
        self.assertEqual(reply.kind, "server_hello")

    def test_other_starttls_protocols_are_refused_explicitly(self):
        with patch.object(CheckContext, "starttls", "irc"):
            reply = transport.send_client_hello(ctx(host="127.0.0.1", port=1))
        self.assertIn("not supported", reply.error)

    def test_server_name_for_a_raw_hello_is_always_ascii_or_absent(self):
        self.assertEqual(transport._hello_server_name("www.example.org."), "www.example.org")
        self.assertEqual(transport._hello_server_name("bücher.example"), "xn--bcher-kva.example")
        for unusable in ("", "192.0.2.1", "2001:db8::1", "a" * 300, "\udcff.example"):
            self.assertEqual(transport._hello_server_name(unusable), "", unusable)

    def test_no_probe_when_cancelled(self):
        event = threading.Event()
        event.set()
        self.assertEqual(transport.send_client_hello(ctx(cancel_event=event)).kind, "error")

    def test_connection_count_is_one_per_probe(self):
        server = ScriptedServer(lambda hello: server_hello())
        self.addCleanup(server.close)
        transport.send_client_hello(ctx(host="127.0.0.1", port=server.port))
        self.assertEqual(len(server.hellos), 1)


# ---------------------------------------------------------------------------------------------
# B3 / B4 / B5 / B6 - against a scripted server and with stubbed replies
# ---------------------------------------------------------------------------------------------


def reply(kind="server_hello", version="TLSv1.2", compression=0, extensions=(), alert_code=None, error=""):
    return ServerReply(kind=kind, version=version, cipher_suite=0xC02F, compression=compression, extensions={code: b"" for code in extensions}, alert=alert_code, error=error)


class CompressionTests(unittest.TestCase):
    def test_no_compression_selected_passes_and_offers_deflate(self):
        server = ScriptedServer(lambda hello: server_hello(compression=0))
        self.addCleanup(server.close)
        outcome = handshake.check_tls_compression(ctx(host="127.0.0.1", port=server.port))
        self.assertEqual(outcome.status, PASS)
        self.assertEqual(hello_compressions(server.hellos[0]), [1, 0])

    def test_compression_selected_fails(self):
        server = ScriptedServer(lambda hello: server_hello(compression=1))
        self.addCleanup(server.close)
        outcome = handshake.check_tls_compression(ctx(host="127.0.0.1", port=server.port))
        self.assertEqual(outcome.status, FAIL)
        self.assertIn("CRIME", outcome.message)

    def test_tls13_only_is_not_applicable_without_any_probe(self):
        with patch.object(handshake, "send_client_hello") as send:
            outcome = handshake.check_tls_compression(ctx(observed_versions=("TLSv1.3",)))
        self.assertEqual(outcome.status, NOT_APPLICABLE)
        send.assert_not_called()

    def test_alert_or_silence_is_inconclusive_never_a_pass(self):
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply("alert", alert_code=40)):
            self.assertEqual(handshake.check_tls_compression(ctx(observed_versions=("TLSv1.2",))).status, INCONCLUSIVE)
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply("error", error="timeout")):
            self.assertEqual(handshake.check_tls_compression(ctx()).status, INCONCLUSIVE)

    def test_unsupported_starttls_is_not_tested(self):
        with patch.object(CheckContext, "starttls", "irc"):
            self.assertEqual(handshake.check_tls_compression(ctx()).status, NOT_TESTED)


class ExtendedMasterSecretTests(unittest.TestCase):
    def test_echoed_extension_passes(self):
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply(extensions=[EXT_EXTENDED_MASTER_SECRET])):
            self.assertEqual(handshake.check_extended_master_secret(ctx()).status, PASS)

    def test_missing_extension_fails(self):
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply()):
            self.assertEqual(handshake.check_extended_master_secret(ctx()).status, FAIL)

    def test_tls13_only_endpoint_is_not_applicable(self):
        self.assertEqual(handshake.check_extended_master_secret(ctx(observed_versions=("TLSv1.3",))).status, NOT_APPLICABLE)

    def test_protocol_version_alert_on_a_tls13_only_server_is_not_applicable(self):
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply("alert", alert_code=ALERT_PROTOCOL_VERSION)):
            self.assertEqual(handshake.check_extended_master_secret(ctx(observed_versions=("TLSv1.3",))).status, NOT_APPLICABLE)

    def test_protocol_version_alert_without_proof_is_inconclusive(self):
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply("alert", alert_code=ALERT_PROTOCOL_VERSION)):
            self.assertEqual(handshake.check_extended_master_secret(ctx()).status, INCONCLUSIVE)

    def test_real_socket_round_trip(self):
        server = ScriptedServer(lambda hello: server_hello(extensions=[(EXT_EXTENDED_MASTER_SECRET, b"")]))
        self.addCleanup(server.close)
        self.assertEqual(handshake.check_extended_master_secret(ctx(host="127.0.0.1", port=server.port)).status, PASS)


class FallbackScsvTests(unittest.TestCase):
    def test_choice_of_the_offered_version(self):
        self.assertEqual(handshake.choose_fallback_version(["TLSv1.2", "TLSv1.3"]), ("TLSv1.2", ""))
        self.assertEqual(handshake.choose_fallback_version(["TLSv1.0", "TLSv1.1", "TLSv1.2"]), ("TLSv1.1", ""))
        self.assertEqual(handshake.choose_fallback_version(["TLSv1.2"])[1], "single_version")
        self.assertIsNone(handshake.choose_fallback_version(["SSLv3", "TLSv1.0"])[0])

    def scripted(self, protected, supported=0x0303):
        def responder(hello):
            if transport.SCSV_FALLBACK in hello_ciphers(hello) and protected and hello_version(hello) < max(supported, 0x0304):
                return alert(ALERT_INAPPROPRIATE_FALLBACK)
            return server_hello(version=hello_version(hello))

        return ScriptedServer(responder)

    def test_protected_server_passes(self):
        server = self.scripted(True)
        self.addCleanup(server.close)
        outcome = handshake.check_fallback_scsv(ctx(host="127.0.0.1", port=server.port, observed_versions=("TLSv1.2", "TLSv1.3")))
        self.assertEqual(outcome.status, PASS)
        self.assertEqual(outcome.observations["offered_version"], "TLSv1.2")
        self.assertEqual(len(server.hellos), 2)  # reference negotiation, then the SCSV probe
        self.assertNotIn(transport.SCSV_FALLBACK, hello_ciphers(server.hellos[0]))
        self.assertIn(transport.SCSV_FALLBACK, hello_ciphers(server.hellos[1]))

    def test_unprotected_server_fails(self):
        server = self.scripted(False)
        self.addCleanup(server.close)
        outcome = handshake.check_fallback_scsv(ctx(host="127.0.0.1", port=server.port, observed_versions=("TLSv1.2", "TLSv1.3")))
        self.assertEqual(outcome.status, FAIL)

    def test_single_version_is_not_applicable_and_unknown_versions_not_tested(self):
        self.assertEqual(handshake.check_fallback_scsv(ctx(observed_versions=("TLSv1.2",))).status, NOT_APPLICABLE)
        self.assertEqual(handshake.check_fallback_scsv(ctx()).status, NOT_TESTED)

    def test_failed_reference_negotiation_gives_no_conclusion(self):
        replies = iter([reply("alert", alert_code=40)])
        with patch.object(handshake, "send_client_hello", lambda *a, **k: next(replies)):
            outcome = handshake.check_fallback_scsv(ctx(observed_versions=("TLSv1.2", "TLSv1.3")))
        self.assertEqual(outcome.status, INCONCLUSIVE)
        self.assertIn("reference negotiation", outcome.message)

    def test_other_alert_on_the_scsv_probe_is_inconclusive(self):
        replies = iter([reply(version="TLSv1.2"), reply("alert", alert_code=40)])
        with patch.object(handshake, "send_client_hello", lambda *a, **k: next(replies)):
            self.assertEqual(handshake.check_fallback_scsv(ctx(observed_versions=("TLSv1.2", "TLSv1.3"))).status, INCONCLUSIVE)


class RenegotiationTests(unittest.TestCase):
    def test_tls13_only_is_not_applicable(self):
        outcome = handshake.check_renegotiation(ctx(observed_versions=("TLSv1.3",)))
        self.assertEqual((outcome.status, outcome.observations["mode"]), (NOT_APPLICABLE, "not_applicable"))

    def test_server_without_rfc5746_is_insecure(self):
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply()):
            outcome = handshake.check_renegotiation(ctx())
        self.assertEqual((outcome.status, outcome.observations["mode"]), (FAIL, "insecure"))

    def test_secure_with_client_initiated_refused(self):
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply(extensions=[EXT_RENEGOTIATION_INFO])), \
                patch.object(handshake, "client_initiated_renegotiation", lambda c: ("refused", "alert")):
            outcome = handshake.check_renegotiation(ctx())
        self.assertEqual((outcome.status, outcome.observations["mode"]), (PASS, "refused"))

    def test_secure_with_client_initiated_accepted_is_flagged(self):
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply(extensions=[EXT_RENEGOTIATION_INFO])), \
                patch.object(handshake, "client_initiated_renegotiation", lambda c: ("accepted", "2nd ServerHello")):
            outcome = handshake.check_renegotiation(ctx())
        self.assertEqual((outcome.status, outcome.observations["mode"], outcome.observations["client_initiated"]), (PASS, "secure", "accepted"))
        self.assertIn("resource exhaustion", outcome.message)

    def test_client_initiated_undetermined_is_reported_as_such(self):
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply(extensions=[EXT_RENEGOTIATION_INFO])), \
                patch.object(handshake, "client_initiated_renegotiation", lambda c: ("undetermined", "x")):
            outcome = handshake.check_renegotiation(ctx())
        self.assertEqual(outcome.observations["client_initiated"], "undetermined")
        self.assertIn("could not be determined", outcome.message)

    def test_unreachable_is_inconclusive(self):
        with patch.object(handshake, "send_client_hello", lambda *a, **k: reply("error", error="timeout")):
            self.assertEqual(handshake.check_renegotiation(ctx()).status, INCONCLUSIVE)

    def test_openssl_is_never_asked_to_enable_legacy_renegotiation(self):
        source = "".join(open(module.__file__).read() for module in (handshake, transport, groups, stapling))
        for dangerous in ("-legacy_renegotiation", "-legacy_server_connect", "UnsafeLegacy", '"-comp"'):
            self.assertNotIn(dangerous, source, dangerous)


# ---------------------------------------------------------------------------------------------
# catalogue, configuration and execution
# ---------------------------------------------------------------------------------------------


class CatalogueTests(unittest.TestCase):
    def test_every_check_has_label_family_and_unique_id(self):
        ids = [spec.check_id for spec in catalog.CATALOG]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), set(catalog.CHECK_LABELS))
        self.assertTrue(all(spec.family in catalog.FAMILIES for spec in catalog.CATALOG))
        self.assertTrue(any(spec.recommended for spec in catalog.CATALOG) and not all(spec.recommended for spec in catalog.CATALOG))

    def test_catalog_dicts_expose_only_implemented_checks(self):
        self.assertEqual([item["id"] for item in catalog.catalog_as_dicts()], list(catalog.CHECK_IDS))

    def test_one_failing_check_does_not_stop_the_others(self):
        def boom(context):
            raise RuntimeError("boom")

        specs = tuple(catalog.CATALOG[:1]) + (catalog.CheckSpec("second", "identity", lambda c: result("second", PASS), False),)
        patched = (catalog.CheckSpec(specs[0].check_id, specs[0].family, boom, True), specs[1])
        with patch.object(catalog, "CATALOG", patched):
            results = catalog.run_complementary_checks([patched[0].check_id, "second"], "192.0.2.1", 443)
        self.assertEqual([r.status for r in results], [ERROR, PASS])

    def test_only_selected_checks_run_in_catalogue_order(self):
        ran = []
        specs = tuple(catalog.CheckSpec(spec.check_id, spec.family, (lambda c, i=spec.check_id: ran.append(i) or result(i, PASS)), spec.recommended) for spec in catalog.CATALOG)
        with patch.object(catalog, "CATALOG", specs):
            catalog.run_complementary_checks(["fallback_scsv", "hostname_san"], "192.0.2.1", 443)
        self.assertEqual(ran, ["hostname_san", "fallback_scsv"])

    def test_cancellation_stops_all_remaining_checks(self):
        event = threading.Event()
        event.set()
        results = catalog.run_complementary_checks(catalog.CHECK_IDS, "192.0.2.1", 443, cancel_event=event)
        self.assertTrue(all(r.status == NOT_TESTED for r in results))

    def test_summarize_observations_skips_nested_values(self):
        text = catalog.summarize_observations({"a": 1, "b": ["x", "y"], "c": {"n": 1}, "d": [{"n": 1}], "e": None})
        self.assertEqual(text, "a: 1 · b: x, y")


class ConfigurationTests(unittest.TestCase):
    def parse(self, checks):
        from tls_scanner.config import parse_tls_checks_config

        return parse_tls_checks_config(checks)

    def test_historical_configuration_selects_nothing(self):
        for checks in (None, {}, {"certificate": {"enabled": True}}, {"tls": None}):
            with self.subTest(checks=checks):
                self.assertEqual(self.parse(checks), ((), 10, 120, {}))

    def test_forms_boolean_and_mapping(self):
        selected, timeout, budget, options = self.parse({"tls": {"fallback_scsv": True, "hostname_san": {"enabled": True}, "tls_compression": False, "timeout_seconds": 5, "time_budget_seconds": 60}})
        self.assertEqual((selected, timeout, budget, options), (("hostname_san", "fallback_scsv"), 5, 60, {}))

    def test_unknown_check_and_invalid_values_are_rejected(self):
        for bad in ({"tls": {"heartbleed": True}}, {"tls": {"hostname_san": "yes"}}, {"tls": {"hostname_san": {"enabled": True, "x": 1}}},
                    {"tls": {"timeout_seconds": 0}}, {"tls": {"timeout_seconds": True}}, {"tls": {"time_budget_seconds": 9}}, {"tls": ["hostname_san"]}):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                self.parse(bad)

    def test_job_built_from_sections_carries_the_selection(self):
        from tls_scanner.config import build_job_from_sections

        legacy = build_job_from_sections({"ports": "443"}, {}, {}, ["192.0.2.1"], None, {"certificate": {"enabled": True}})
        self.assertEqual((legacy.tls_checks, legacy.tls_check_results), ((), {}))
        new = build_job_from_sections({"ports": "443"}, {}, {}, ["192.0.2.1"], None, {"tls": {"ocsp_stapling": {"enabled": True}}})
        self.assertEqual(new.tls_checks, ("ocsp_stapling",))

    def test_profile_validation_uses_the_same_parser(self):
        import importlib.util

        if importlib.util.find_spec("tls_scan_app") is None:
            self.skipTest("backend package not importable here")
        from tls_scan_app.services.planner import PlanError, validate_profile_content

        validate_profile_content({"scan": {"ports": "443"}, "checks": {"tls": {"hostname_san": {"enabled": True}}}})
        with self.assertRaises(PlanError):
            validate_profile_content({"scan": {"ports": "443"}, "checks": {"tls": {"nope": True}}})


if __name__ == "__main__":
    unittest.main()
