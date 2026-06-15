import socket
import unittest
from unittest.mock import patch
from argparse import ArgumentTypeError

import Scan_nmap_TLS3 as scanner


class NormalizeTargetsTests(unittest.TestCase):
    def test_normalizes_comma_separated_targets_for_nmap(self):
        targets = "192.168.1.0/24, 10.0.0.5,web.example.com"

        self.assertEqual(
            scanner.normalize_targets(targets),
            "192.168.1.0/24 10.0.0.5 web.example.com",
        )


class ParsePortsTests(unittest.TestCase):
    def test_uses_multiple_ports_and_ranges(self):
        self.assertEqual(
            scanner.parse_ports("443, 8443, 9000-9010"),
            "443,8443,9000-9010",
        )

    def test_accepts_all(self):
        self.assertEqual(scanner.parse_ports("all"), "all")

    def test_accepts_fast(self):
        self.assertEqual(scanner.parse_ports("fast"), "fast")

    def test_rejects_invalid_port(self):
        with self.assertRaises(ArgumentTypeError):
            scanner.parse_ports("443,70000")


class DiscoverPortsTests(unittest.TestCase):
    def test_scans_all_tcp_ports_and_returns_only_open_ports(self):
        class FakePortScanner:
            def __init__(self):
                self.scan_call = None
                self.host_data = {
                    "192.0.2.10": {
                        "tcp": {
                            22: {"state": "open"},
                            80: {"state": "closed"},
                            443: {"state": "open"},
                        }
                    }
                }

            def scan(self, **kwargs):
                self.scan_call = kwargs

            def all_hosts(self):
                return list(self.host_data)

            def __getitem__(self, host):
                return self.host_data[host]

        fake_scanner = FakePortScanner()

        class FakeNmap:
            @staticmethod
            def PortScanner():
                return fake_scanner

        result = scanner.discover_open_tcp_ports(
            FakeNmap,
            "192.0.2.10",
            "all",
        )

        self.assertEqual(result, {"192.0.2.10": [22, 443]})
        self.assertEqual(fake_scanner.scan_call["ports"], "1-65535")
        self.assertEqual(
            fake_scanner.scan_call["arguments"],
            "-T4 --open --max-retries 1",
        )

    def test_fast_mode_uses_nmap_common_ports(self):
        class FakePortScanner:
            def __init__(self):
                self.scan_call = None

            def scan(self, **kwargs):
                self.scan_call = kwargs

            def all_hosts(self):
                return []

        fake_scanner = FakePortScanner()

        class FakeNmap:
            @staticmethod
            def PortScanner():
                return fake_scanner

        scanner.discover_open_tcp_ports(FakeNmap, "192.0.2.10", "fast")

        self.assertNotIn("ports", fake_scanner.scan_call)
        self.assertEqual(
            fake_scanner.scan_call["arguments"],
            "-F -T4 --open --max-retries 1",
        )


class ResolveFqdnTests(unittest.TestCase):
    @patch("Scan_nmap_TLS3.socket.gethostbyaddr")
    def test_returns_resolved_fqdn(self, gethostbyaddr):
        gethostbyaddr.return_value = ("host.example.com.", [], ["192.0.2.10"])

        self.assertEqual(scanner.resolve_fqdn("192.0.2.10"), "host.example.com")

    @patch("Scan_nmap_TLS3.socket.gethostbyaddr")
    def test_returns_empty_value_when_reverse_dns_fails(self, gethostbyaddr):
        gethostbyaddr.side_effect = socket.herror

        self.assertEqual(scanner.resolve_fqdn("192.0.2.10"), "")


class ComplianceTests(unittest.TestCase):
    def test_rejects_tls_1_0(self):
        result = scanner.check_compliance(
            "TLSv1.0",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, "KO")

    def test_rejects_md5_cipher(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_RSA_WITH_RC4_128_MD5",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, "KO")

    def test_rejects_sha1_certificate_signature(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "2099-01-01",
            "Signature Algorithm: sha1WithRSAEncryption",
            "RSA",
            3072,
        )

        self.assertEqual(result, "KO")

    def test_ignores_sha1_certificate_fingerprint(self):
        certificate_output = """
Signature Algorithm: sha256WithRSAEncryption
MD5: aa:bb:cc
SHA-1: 11:22:33
"""
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "2099-01-01",
            certificate_output,
            "RSA",
            4096,
        )

        self.assertEqual(result, "OK")

    def test_accepts_cbc_cipher_with_sha384(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, "OK")

    def test_accepts_dhe_cbc_cipher_with_sha256(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, "OK")

    def test_rejects_cbc_cipher_with_sha1(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, "KO")

    def test_rejects_static_rsa_key_exchange(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, "KO")

    def test_rejects_rsa_key_smaller_than_3072_bits(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "2099-01-01",
            "",
            "RSA",
            2048,
        )

        self.assertEqual(result, "KO")

    def test_accepts_tls_1_3_with_valid_certificate(self):
        result = scanner.check_compliance(
            "TLSv1.3",
            "TLS_AES_256_GCM_SHA384",
            "2099-01-01",
            "Signature Algorithm: sha256WithRSAEncryption",
            "RSA",
            3072,
        )

        self.assertEqual(result, "OK")

    def test_accepts_tls_1_2_with_ecdhe_and_aead(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, "OK")

    def test_accepts_tls_1_2_with_dhe_and_ccm(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_DHE_RSA_WITH_AES_256_CCM",
            "2099-01-01",
            "Signature Algorithm: sha256WithRSAEncryption",
            "EC",
            256,
        )

        self.assertEqual(result, "OK")


class CipherSuiteExtractionTests(unittest.TestCase):
    def test_extracts_every_cipher_suite_with_its_tls_version(self):
        cipher_output = """
TLSv1.0:
  ciphers:
    TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
TLSv1.2:
  ciphers:
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
    TLS_RSA_WITH_AES_256_GCM_SHA384 (rsa 2048) - A
"""

        self.assertEqual(
            scanner.extract_cipher_suites(cipher_output),
            [
                ("TLSv1.0", "TLS_RSA_WITH_AES_128_CBC_SHA"),
                ("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
                ("TLSv1.2", "TLS_RSA_WITH_AES_256_GCM_SHA384"),
            ],
        )


class PublicKeyTests(unittest.TestCase):
    def test_extracts_rsa_key_size(self):
        certificate_output = """
Public Key type: rsa
Public Key bits: 3072
"""

        self.assertEqual(
            scanner.extract_public_key(certificate_output),
            ("RSA", 3072),
        )

    def test_extracts_certificate_signature_algorithm(self):
        certificate_output = """
Signature Algorithm: sha256WithRSAEncryption
SHA-1: 11:22:33
"""

        self.assertEqual(
            scanner.extract_signature_algorithm(certificate_output),
            "sha256WithRSAEncryption",
        )


class HostGradeTests(unittest.TestCase):
    def finding(
        self,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AKE_WITH_AES_256_GCM_SHA384",
        cert_validity="2099-01-01",
        certificate_output="Signature Algorithm: sha256WithRSAEncryption",
        public_key_type="RSA",
        public_key_bits=3072,
    ):
        return {
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "cert_validity": cert_validity,
            "certificate_output": certificate_output,
            "public_key_type": public_key_type,
            "public_key_bits": public_key_bits,
        }

    def test_returns_a_plus_for_strong_tls_1_3_host(self):
        self.assertEqual(scanner.calculate_host_grade([self.finding()]), "A+")

    def test_returns_a_without_tls_1_3(self):
        finding = self.finding(
            tls_version="TLSv1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        )

        self.assertEqual(scanner.calculate_host_grade([finding]), "A")

    def test_returns_worst_grade_for_every_host_finding(self):
        md5_finding = self.finding(
            tls_version="TLSv1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_MD5",
        )

        self.assertEqual(
            scanner.calculate_host_grade([self.finding(), md5_finding]),
            "D",
        )

    def test_returns_b_for_rsa_2048(self):
        finding = self.finding(public_key_bits=2048)

        self.assertEqual(scanner.calculate_host_grade([finding]), "B")

    def test_returns_f_for_expired_certificate(self):
        finding = self.finding(cert_validity="2000-01-01")

        self.assertEqual(scanner.calculate_host_grade([finding]), "F")

    def test_applies_same_worst_grade_to_every_row_for_host(self):
        results = [
            ["192.0.2.10", "host.example", 443, "TLSv1.3"],
            ["192.0.2.10", "host.example", 8443, "TLSv1.2"],
        ]
        findings = {
            "192.0.2.10": [
                self.finding(),
                self.finding(
                    tls_version="TLSv1.0",
                    cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
                ),
            ]
        }

        scanner.apply_host_grades(results, findings)

        self.assertEqual(results[0][3], "D")
        self.assertEqual(results[1][3], "D")

    def test_returns_f_for_unknown_tls_version(self):
        finding = self.finding(tls_version="N/A")

        self.assertEqual(scanner.calculate_host_grade([finding]), "F")


if __name__ == "__main__":
    unittest.main()
