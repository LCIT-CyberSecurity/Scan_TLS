"""A service that holds the connection open after (or instead of) the TLS handshake must not be reported as a scanner error."""
import datetime
import subprocess
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tls_scanner import pki


def make_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "freebox.home")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def timeout(stdout: bytes | None, stderr: bytes | None = b"") -> subprocess.TimeoutExpired:
    return subprocess.TimeoutExpired(["openssl", "s_client"], 10, output=stdout, stderr=stderr)


class ChainCollectionTimeoutTests(unittest.TestCase):
    def collect(self, error):
        with patch("tls_scanner.pki.shutil.which", return_value="/usr/bin/openssl"), patch("tls_scanner.pki.subprocess.run", side_effect=error):
            return pki.collect_peer_certificate_chain("192.168.1.37", 9000, "freebox-mini.home")

    def test_the_chain_printed_before_the_timeout_is_used(self):
        chain = self.collect(timeout(b"CONNECTED(00000003)\n" + make_pem() + b"\n"))
        self.assertEqual(chain.status, "ok")
        self.assertEqual(len(chain.certificates), 1)

    def test_a_silent_service_is_not_tested_with_a_clear_reason_and_not_an_error(self):
        chain = self.collect(timeout(None, None))
        self.assertEqual(chain.certificates, ())
        self.assertEqual(chain.status, "not_tested")
        self.assertIn("no TLS handshake completed within 10 seconds", chain.error)

    def test_a_handshake_that_fails_is_explained_instead_of_echoing_the_connected_line(self):
        class Done:
            stdout = b"CONNECTED(00000003)\n"
            stderr = b"4067:error:0A00010B:SSL routines:ssl3_get_record:wrong version number\n---\nno peer certificate available\n"
        with patch("tls_scanner.pki.shutil.which", return_value="/usr/bin/openssl"), patch("tls_scanner.pki.subprocess.run", return_value=Done()):
            chain = pki.collect_peer_certificate_chain("192.168.1.5", 389)
        self.assertEqual(chain.status, "not_tested")
        self.assertNotEqual(chain.error, "CONNECTED(00000003)")
        self.assertIn("did not complete a TLS handshake", chain.error)
        self.assertIn("wrong version number", chain.error)

    def test_only_noise_gives_the_generic_explanation(self):
        self.assertTrue(pki.no_chain_reason(b"CONNECTED(00000003)\n---\nDONE\n").endswith("needing STARTTLS)"))

    def test_other_failures_stay_errors(self):
        chain = self.collect(OSError("openssl crashed"))
        self.assertEqual(chain.status, "error")


if __name__ == "__main__":
    unittest.main()
