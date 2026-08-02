"""
Generate a non-sensitive professional TLS Scan demo report.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tls_scanner import EncryptionPolicy, ScanJob, build_export_paths, write_exports


def row(ip, fqdn, port, grade, tls, cipher, public_key, expiry, crypto, self_signed, days, issuer, subject, san, key_type, key_size, signature, compliance, reason, key_exchange=None):
    base = [ip, fqdn, port, grade, tls, cipher, public_key, expiry]
    if key_exchange is not None:
        base.append(key_exchange)
    base.extend([crypto, self_signed, days, issuer, subject, san, key_type, key_size, signature, compliance, reason])
    return base


def demo_results():
    return [
        row("198.51.100.10", "secure.demo.example", 443, "A+", "TLSv1.3", "TLS_AES_256_GCM_SHA384", "RSA 3072 bits", "2099-01-01", "RSA 3072 / SHA-256", "no", 26418, "Demo Public CA", "CN=secure.demo.example", "secure.demo.example", "RSA", 3072, "sha256WithRSAEncryption", "OK", "", "X25519MLKEM768"),
        row("198.51.100.11", "legacy.demo.example", 443, "D", "TLSv1.0", "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA 2048 bits", "2099-01-01", "RSA 2048 / SHA-256", "no", 26418, "Demo Public CA", "CN=legacy.demo.example", "legacy.demo.example", "RSA", 2048, "sha256WithRSAEncryption", "KO", "TLS 1.0 detected", "Not supported"),
        row("198.51.100.12", "weak-cipher.demo.example", 443, "C", "TLSv1.2", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA 2048 bits", "2099-01-01", "RSA 2048 / SHA-256", "no", 26418, "Demo Public CA", "CN=weak-cipher.demo.example", "weak-cipher.demo.example", "RSA", 2048, "sha256WithRSAEncryption", "KO", "Cipher suite", "Not supported"),
        row("198.51.100.13", "expired.demo.example", 443, "F", "TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "RSA 2048 bits", "2025-01-01", "RSA 2048 / SHA-256", "no", -577, "Demo Public CA", "CN=expired.demo.example", "expired.demo.example", "RSA", 2048, "sha256WithRSAEncryption", "KO", "Certificate expired", "Not supported"),
        row("198.51.100.14", "expiring.demo.example", 443, "A", "TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "RSA 3072 bits", "2026-08-20", "RSA 3072 / SHA-256", "no", 19, "Demo Public CA", "CN=expiring.demo.example", "expiring.demo.example", "RSA", 3072, "sha256WithRSAEncryption", "OK", "", "Not supported"),
        row("198.51.100.15", "self-signed.demo.example", 8443, "B", "TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "RSA 2048 bits", "2099-01-01", "RSA 2048 / SHA-256", "yes", 26418, "CN=self-signed.demo.example", "CN=self-signed.demo.example", "self-signed.demo.example", "RSA", 2048, "sha256WithRSAEncryption", "OK", "", "Not supported"),
        row("198.51.100.16", "small-key.demo.example", 443, "F", "TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "RSA 1024 bits", "2099-01-01", "RSA 1024 / SHA-256", "no", 26418, "Demo Public CA", "CN=small-key.demo.example", "small-key.demo.example", "RSA", 1024, "sha256WithRSAEncryption", "KO", "RSA key size", "Not supported"),
        row("198.51.100.17", "sha1.demo.example", 443, "C", "TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "RSA 2048 bits", "2099-01-01", "RSA 2048 / SHA-1", "no", 26418, "Demo Public CA", "CN=sha1.demo.example", "sha1.demo.example", "RSA", 2048, "sha1WithRSAEncryption", "KO", "Signature hash", "Not supported"),
        row("198.51.100.18", "pki-not-tested.demo.example", 9443, "A", "TLSv1.2", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDSA 256 bits", "2099-01-01", "ECDSA 256 / SHA-256", "unknown", 26418, "Demo Internal CA", "CN=pki-not-tested.demo.example", "pki-not-tested.demo.example", "ECDSA", 256, "ecdsa-with-SHA256", "OK", "", "Not supported"),
        row("198.51.100.19", "unreachable.demo.example", 443, "F", "N/A", "N/A", "Unknown", "N/A", "Unknown / unknown", "unknown", "unknown", "-", "-", "-", "Unknown", "unknown", "unknown", "ERROR", "Scan error", "Not supported"),
        row("198.51.100.11", "legacy.demo.example", 8443, "D", "TLSv1.1", "TLS_RSA_WITH_AES_256_CBC_SHA", "RSA 2048 bits", "2099-01-01", "RSA 2048 / SHA-256", "no", 26418, "Demo Public CA", "CN=legacy.demo.example", "legacy.demo.example", "RSA", 2048, "sha256WithRSAEncryption", "KO", "TLS 1.1 detected", "Not supported"),
    ]


def main():
    job = ScanJob(
        targets="demo.example",
        ports="443,8443,9443",
        crypto="pqc",
        ip=False,
        report_name="tls_scan_demo",
        frequency="demo",
        scan_run_id="demo-run-2026-08-01",
        export_directory="scan_reports",
        export_formats=("csv", "cbom", "md", "html", "pdf"),
        policies=(EncryptionPolicy(name="anssi_encryption_policy", version="1.0", description="Demo ANSSI-compatible policy."),),
    )
    paths = build_export_paths(job, "2026-08-01-151245")
    written = write_exports(demo_results(), job, "2026-08-01T15:12:45+02:00", paths, 42.5)
    for item in written:
        print(item)


if __name__ == "__main__":
    main()
