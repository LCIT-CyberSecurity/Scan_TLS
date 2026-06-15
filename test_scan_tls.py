import socket
import unittest
from unittest.mock import patch

import Scan_nmap_TLS3 as scanner


class NormalizeTargetsTests(unittest.TestCase):
    def test_normalizes_comma_separated_targets_for_nmap(self):
        targets = "192.168.1.0/24, 10.0.0.5,web.example.com"

        self.assertEqual(
            scanner.normalize_targets(targets),
            "192.168.1.0/24 10.0.0.5 web.example.com",
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


if __name__ == "__main__":
    unittest.main()
