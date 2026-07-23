import socket
import tempfile
import unittest
from argparse import ArgumentTypeError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import Scan_nmap_TLS3 as scanner


# Input normalization and command-line port validation.
class NormalizeTargetsTests(unittest.TestCase):
    def test_normalizes_comma_separated_targets_for_nmap(self):
        targets = "192.168.1.0/24, 10.0.0.5,web.example.com"

        self.assertEqual(
            scanner.normalize_targets(targets),
            "192.168.1.0/24 10.0.0.5 web.example.com",
        )


class ParsePortsTests(unittest.TestCase):
    @patch("Scan_nmap_TLS3.sys.argv", ["Scan_nmap_TLS3.py"])
    def test_accepts_no_arguments_for_default_config_mode(self):
        args = scanner.parse_args()

        self.assertIsNone(args.targets)

    @patch("Scan_nmap_TLS3.sys.argv", ["Scan_nmap_TLS3.py", "192.0.2.10"])
    def test_defaults_to_fast_port_discovery(self):
        self.assertEqual(scanner.parse_args().ports, "fast")

    @patch("Scan_nmap_TLS3.sys.argv", ["Scan_nmap_TLS3.py", "192.0.2.10"])
    def test_defaults_to_standard_crypto_criterion(self):
        self.assertEqual(scanner.parse_args().crypto, "standard")

    @patch(
        "Scan_nmap_TLS3.sys.argv",
        ["Scan_nmap_TLS3.py", "-c", "pqc", "192.0.2.10"],
    )
    def test_accepts_pqc_crypto_criterion(self):
        self.assertEqual(scanner.parse_args().crypto, "pqc")

    @patch("Scan_nmap_TLS3.sys.argv", ["Scan_nmap_TLS3.py", "192.0.2.10"])
    def test_defaults_to_info_file_logging(self):
        args = scanner.parse_args()

        self.assertEqual(args.log_level, "info")
        self.assertEqual(args.log_file, scanner.DEFAULT_LOG_FILE)
        self.assertFalse(args.no_log_file)

    @patch(
        "Scan_nmap_TLS3.sys.argv",
        [
            "Scan_nmap_TLS3.py",
            "--log-level",
            "debug",
            "--log-file",
            "custom.log",
            "192.0.2.10",
        ],
    )
    def test_accepts_log_level_and_file(self):
        args = scanner.parse_args()

        self.assertEqual(args.log_level, "debug")
        self.assertEqual(args.log_file, "custom.log")

    @patch(
        "Scan_nmap_TLS3.sys.argv",
        ["Scan_nmap_TLS3.py", "--no-log-file", "192.0.2.10"],
    )
    def test_accepts_disabling_file_logging(self):
        self.assertTrue(scanner.parse_args().no_log_file)

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


class ExportArgumentTests(unittest.TestCase):
    @patch(
        "Scan_nmap_TLS3.sys.argv",
        ["Scan_nmap_TLS3.py", "192.0.2.10", "results.csv"],
    )
    def test_accepts_legacy_positional_csv_filename(self):
        self.assertEqual(scanner.parse_args().csv_filename, "results.csv")

    @patch(
        "Scan_nmap_TLS3.sys.argv",
        ["Scan_nmap_TLS3.py", "192.0.2.10", "-e", "results.csv"],
    )
    def test_accepts_export_option(self):
        self.assertEqual(scanner.parse_args().csv_filename, "results.csv")

    @patch(
        "Scan_nmap_TLS3.sys.argv",
        [
            "Scan_nmap_TLS3.py",
            "192.0.2.10",
            "legacy.csv",
            "-e",
            "results.csv",
        ],
    )
    def test_rejects_both_export_syntaxes(self):
        with self.assertRaises(SystemExit):
            scanner.parse_args()

    @patch(
        "Scan_nmap_TLS3.sys.argv",
        ["Scan_nmap_TLS3.py", "192.0.2.10", "-e", "results.cbom.json"],
    )
    def test_detects_cbom_export(self):
        args = scanner.parse_args()

        self.assertEqual(args.csv_filename, "results.cbom.json")
        self.assertEqual(args.export_format, "cbom")

    @patch(
        "Scan_nmap_TLS3.sys.argv",
        ["Scan_nmap_TLS3.py", "192.0.2.10", "-e", "results.json"],
    )
    def test_rejects_ambiguous_export_extension(self):
        with self.assertRaises(SystemExit):
            scanner.parse_args()


class ScanJobTests(unittest.TestCase):
    @patch(
        "Scan_nmap_TLS3.sys.argv",
        [
            "Scan_nmap_TLS3.py",
            "-i",
            "-c",
            "pqc",
            "-p",
            "443,8443",
            "-e",
            "results.cbom.json",
            "--log-level",
            "debug",
            "--no-log-file",
            "192.0.2.10",
        ],
    )
    def test_builds_scan_job_from_cli_arguments(self):
        job = scanner.build_cli_scan_job(scanner.parse_args())

        self.assertEqual(job.targets, "192.0.2.10")
        self.assertEqual(job.ports, "443,8443")
        self.assertEqual(job.crypto, "pqc")
        self.assertTrue(job.ip)
        self.assertEqual(job.csv_filename, "results.cbom.json")
        self.assertEqual(job.export_format, "cbom")
        self.assertEqual(job.log_level, "debug")
        self.assertIsNone(job.log_file)


class ConfigTests(unittest.TestCase):
    def write_config(self, content):
        config_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".yaml",
            delete=False,
        )
        with config_file:
            config_file.write(content)
        return config_file.name

    def test_builds_scan_job_from_yaml_config(self):
        config_path = self.write_config(
            """
scan:
  targets:
    - 192.0.2.10
    - host.example
  ports: 443,8443
  crypto: standard
  resolve_dns: false
export:
  filename: results.csv
logging:
  level: debug
  file: audit.log
"""
        )

        try:
            with patch(
                "Scan_nmap_TLS3.sys.argv",
                ["Scan_nmap_TLS3.py", "--config", config_path],
            ):
                job = scanner.build_scan_job(scanner.parse_args())
        finally:
            Path(config_path).unlink()

        self.assertEqual(job.targets, "192.0.2.10,host.example")
        self.assertEqual(job.ports, "443,8443")
        self.assertEqual(job.crypto, "standard")
        self.assertTrue(job.ip)
        self.assertEqual(job.csv_filename, "results.csv")
        self.assertEqual(job.export_format, "csv")
        self.assertEqual(job.log_level, "debug")
        self.assertEqual(job.log_file, "audit.log")

    def test_cli_explicit_values_override_yaml_config(self):
        config_path = self.write_config(
            """
scan:
  targets:
    - 192.0.2.10
  ports: fast
  crypto: standard
  resolve_dns: true
logging:
  level: info
  file: audit.log
"""
        )

        try:
            with patch(
                "Scan_nmap_TLS3.sys.argv",
                [
                    "Scan_nmap_TLS3.py",
                    "--config",
                    config_path,
                    "-p",
                    "443",
                    "-c",
                    "pqc",
                    "--no-log-file",
                    "host.example",
                ],
            ):
                job = scanner.build_scan_job(scanner.parse_args())
        finally:
            Path(config_path).unlink()

        self.assertEqual(job.targets, "host.example")
        self.assertEqual(job.ports, "443")
        self.assertEqual(job.crypto, "pqc")
        self.assertIsNone(job.log_file)

    def test_rejects_invalid_yaml_ports_with_config_error(self):
        config_path = self.write_config(
            """
scan:
  targets: example.com
  ports: 70000
"""
        )

        try:
            with patch(
                "Scan_nmap_TLS3.sys.argv",
                ["Scan_nmap_TLS3.py", "--config", config_path],
            ):
                with self.assertRaisesRegex(
                    scanner.ConfigError,
                    "scan.ports is invalid",
                ):
                    scanner.build_scan_job(scanner.parse_args())
        finally:
            Path(config_path).unlink()

    def test_rejects_missing_yaml_config_file(self):
        with self.assertRaisesRegex(scanner.ConfigError, "Unable to read config file"):
            scanner.load_yaml_config("/tmp/scan-tls-missing-config.yaml")

    def test_rejects_invalid_yaml_syntax(self):
        config_path = self.write_config("scan: [unterminated\n")

        try:
            with self.assertRaisesRegex(scanner.ConfigError, "Invalid YAML config file"):
                scanner.load_yaml_config(config_path)
        finally:
            Path(config_path).unlink()

    def test_rejects_yaml_config_without_targets(self):
        config_path = self.write_config(
            """
scan:
  ports: 443
"""
        )

        try:
            with patch(
                "Scan_nmap_TLS3.sys.argv",
                ["Scan_nmap_TLS3.py", "--config", config_path],
            ):
                with self.assertRaisesRegex(scanner.ConfigError, "scan.targets is required"):
                    scanner.build_scan_job(scanner.parse_args())
        finally:
            Path(config_path).unlink()

    def test_rejects_invalid_yaml_export_extension(self):
        config_path = self.write_config(
            """
scan:
  targets: example.com
export:
  filename: results.json
"""
        )

        try:
            with patch(
                "Scan_nmap_TLS3.sys.argv",
                ["Scan_nmap_TLS3.py", "--config", config_path],
            ):
                with self.assertRaisesRegex(
                    scanner.ConfigError,
                    "export.filename must end with",
                ):
                    scanner.build_scan_job(scanner.parse_args())
        finally:
            Path(config_path).unlink()

    def test_builds_report_from_target_group_and_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            targets_dir = temp_path / "targets"
            policies_dir = temp_path / "policies"
            targets_dir.mkdir()
            policies_dir.mkdir()
            (targets_dir / "external.yaml").write_text(
                """
name: external_public_endpoints
description: Public endpoints.
targets:
  fqdn:
    - example.com
  ip:
    - 192.0.2.10
  subnets:
    - 192.0.2.0/24
""",
                encoding="utf-8",
            )
            (policies_dir / "anssi.yaml").write_text(
                """
name: anssi_encryption_policy
version: "1.0"
description: ANSSI policy.
tls:
  allowed_versions:
    - TLSv1.2
    - TLSv1.3
  allowed_cipher_algorithms:
    - AES-GCM
  allowed_signature_hashes:
    - SHA-256
  minimum_rsa_bits: 2048
""",
                encoding="utf-8",
            )
            config = scanner.load_yaml_config(
                self.write_config(
                    """
defaults:
  scan:
    ports: fast
    crypto: standard
    resolve_dns: true
  export:
    directory: scan_reports
    formats:
      - csv
      - cbom
      - md
  logging:
    level: debug
    file: audit.log
reports:
  - name: external_anssi_weekly
    frequency: weekly
    target_groups:
      - external_public_endpoints
    encryption_policies:
      mode: strict_all
      names:
        - anssi_encryption_policy
"""
                )
            )

            with patch("Scan_nmap_TLS3.DEFAULT_TARGETS_DIR", str(targets_dir)), patch(
                "Scan_nmap_TLS3.DEFAULT_POLICIES_DIR", str(policies_dir)
            ):
                job = scanner.build_config_scan_job(config, "external_anssi_weekly")

        self.assertEqual(job.report_name, "external_anssi_weekly")
        self.assertEqual(job.frequency, "weekly")
        self.assertEqual(job.targets, "example.com,192.0.2.10,192.0.2.0/24")
        self.assertEqual(job.export_formats, ("csv", "cbom", "md"))
        self.assertEqual(job.target_groups[0].name, "external_public_endpoints")
        self.assertEqual(job.policies[0].name, "anssi_encryption_policy")
        self.assertEqual(job.log_level, "debug")

    def test_requires_report_name_when_multiple_reports_are_configured(self):
        config = {
            "reports": [
                {"name": "external_weekly"},
                {"name": "smtp_monthly"},
            ]
        }

        with self.assertRaisesRegex(scanner.ConfigError, "multiple reports configured"):
            scanner.select_config_report(config)

    def test_builds_timestamped_export_paths(self):
        job = scanner.ScanJob(
            targets="example.com",
            ports="443",
            crypto="standard",
            ip=False,
            report_name="external_anssi_weekly",
            export_directory="scan_reports",
            export_formats=("csv", "cbom", "md"),
        )

        paths = scanner.build_export_paths(job, "2026-07-23-143012")

        self.assertEqual(
            str(paths["csv"]),
            "scan_reports/2026-07-23-143012_external_anssi_weekly.csv",
        )
        self.assertEqual(
            str(paths["cbom"]),
            "scan_reports/2026-07-23-143012_external_anssi_weekly.cbom.json",
        )
        self.assertEqual(
            str(paths["md"]),
            "scan_reports/2026-07-23-143012_external_anssi_weekly.md",
        )

    def test_builds_readable_markdown_report(self):
        job = scanner.ScanJob(
            targets="example.com",
            ports="443",
            crypto="standard",
            ip=False,
            scan_run_id="run-123",
            report_name="external_anssi_weekly",
            frequency="weekly",
            target_groups=(
                scanner.TargetGroup(
                    name="external_public_endpoints",
                    targets=("example.com",),
                    description="Public endpoints.",
                ),
            ),
            policies=(
                scanner.EncryptionPolicy(
                    name="anssi_encryption_policy",
                    version="1.0",
                    description="ANSSI policy.",
                ),
            ),
        )
        results = [
            [
                "192.0.2.10",
                "example.com",
                443,
                "C",
                "TLSv1.1",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "RSA 2048 bits",
                "Valid",
                "KO",
                "TLS 1.1 detected",
            ],
            [
                "192.0.2.11",
                "secure.example.com",
                443,
                "A",
                "TLSv1.3",
                "TLS_AES_256_GCM_SHA384",
                "RSA 3072 bits",
                "Valid",
                "OK",
                "",
            ],
        ]

        markdown = scanner.build_markdown_report(
            results,
            job,
            "2026-07-23T14:30:12+02:00",
        )

        self.assertIn("# TLS Scan Dashboard - external_anssi_weekly", markdown)
        self.assertIn("## Dashboard", markdown)
        self.assertIn("```mermaid", markdown)
        self.assertIn("Hosts conformes", markdown)
        self.assertIn("Hosts non conformes", markdown)
        self.assertIn("### Répartition des grades", markdown)
        self.assertIn("### Top raisons de non-conformité", markdown)
        self.assertIn("## Conformité par host", markdown)
        self.assertIn("port 443: TLS 1.1 detected", markdown)
        self.assertIn("Tous les contrôles observés sont conformes.", markdown)
        self.assertIn("Scan run ID", markdown)
        self.assertIn("run-123", markdown)
        self.assertIn("external_public_endpoints", markdown)
        self.assertIn("anssi_encryption_policy v1.0", markdown)
        self.assertIn("## Actions prioritaires", markdown)
        self.assertIn("<details>", markdown)


class LoggingTests(unittest.TestCase):
    def test_configures_file_logging_with_run_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = f"{temp_dir}/scan.log"
            job = scanner.ScanJob(
                targets="192.0.2.10",
                ports="443",
                crypto="standard",
                ip=False,
                log_file=log_file,
                scan_run_id="run-123",
            )

            logger = scanner.configure_logging(job)
            logger.info("scan_start targets=%s", job.targets)

            with open(log_file, encoding="utf-8") as file:
                log_text = file.read()

        self.assertIn("INFO run_id=run-123 scan_start targets=192.0.2.10", log_text)


class CsvExportTests(unittest.TestCase):
    def test_appends_scan_timestamp_and_parameters(self):
        args = SimpleNamespace(
            crypto="standard",
            targets="192.0.2.0/24,host.example",
            ports="fast",
            ip=False,
        )
        results = [["finding"]]

        headers, rows = scanner.build_csv_export(
            results,
            args,
            "2026-06-21T14:00:00Z",
        )

        self.assertEqual(
            headers[-5:],
            [
                "Scan Timestamp",
                "Scan Targets",
                "Port Selection",
                "Crypto Profile",
                "DNS Resolution",
            ],
        )
        self.assertEqual(
            rows[0][-5:],
            [
                "2026-06-21T14:00:00Z",
                args.targets,
                "fast",
                "standard",
                "enabled",
            ],
        )
class CbomExportTests(unittest.TestCase):
    def test_builds_cyclonedx_cryptographic_assets(self):
        results = [
            [
                "192.0.2.10",
                "host.example",
                443,
                "A+",
                "TLSv1.3",
                "TLS_AES_256_GCM_SHA384",
                "RSA 3072 bits",
                "2099-01-01",
                "OK",
                "",
            ]
        ]

        cbom = scanner.build_cbom(results)

        self.assertEqual(cbom["bomFormat"], "CycloneDX")
        self.assertEqual(cbom["specVersion"], "1.6")
        self.assertEqual(cbom["metadata"]["lifecycles"], [{"phase": "discovery"}])
        asset_types = {
            component["cryptoProperties"]["assetType"]
            for component in cbom["components"]
        }
        self.assertEqual(
            asset_types,
            {"algorithm", "related-crypto-material", "protocol"},
        )
        protocol = next(
            component
            for component in cbom["components"]
            if component["cryptoProperties"]["assetType"] == "protocol"
        )
        protocol_properties = protocol["cryptoProperties"]["protocolProperties"]
        self.assertEqual(protocol_properties["type"], "tls")
        self.assertEqual(protocol_properties["version"], "1.3")
        self.assertEqual(
            protocol_properties["cipherSuites"],
            [{"name": "TLS_AES_256_GCM_SHA384"}],
        )


# Nmap port-discovery behavior without performing network scans.
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
            FakeTqdm,
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

        scanner.discover_open_tcp_ports(
            FakeNmap,
            FakeTqdm,
            "192.0.2.10",
            "fast",
        )

        self.assertNotIn("ports", fake_scanner.scan_call)
        self.assertEqual(
            fake_scanner.scan_call["arguments"],
            "-F -T4 --open --max-retries 1",
        )


# Minimal tqdm replacement used to test progress handling deterministically.
class FakeTqdm:
    def __init__(self, *args, **kwargs):
        self.closed = False
        self.updates = 0

    def update(self, value):
        self.updates += value

    def close(self):
        self.closed = True


# Progress display lifecycle and background scan error propagation.
class ScanProgressTests(unittest.TestCase):
    def test_runs_scan_and_closes_progress_bar(self):
        class FakeScanner:
            def __init__(self):
                self.scan_options = None

            def scan(self, **kwargs):
                self.scan_options = kwargs

        fake_scanner = FakeScanner()
        progress_instances = []

        def fake_tqdm(*args, **kwargs):
            progress = FakeTqdm(*args, **kwargs)
            progress_instances.append(progress)
            return progress

        scanner.run_scan_with_progress(
            fake_scanner,
            fake_tqdm,
            "TLS scan",
            hosts="192.0.2.10",
            ports="443",
        )

        self.assertEqual(
            fake_scanner.scan_options,
            {"hosts": "192.0.2.10", "ports": "443"},
        )
        self.assertTrue(progress_instances[0].closed)

    def test_propagates_scan_error(self):
        class FailingScanner:
            def scan(self, **kwargs):
                raise RuntimeError("scan failed")

        with self.assertRaisesRegex(RuntimeError, "scan failed"):
            scanner.run_scan_with_progress(
                FailingScanner(),
                FakeTqdm,
                "TLS scan",
                hosts="192.0.2.10",
            )


# Reverse DNS resolution and failure fallback.
class ResolveFqdnTests(unittest.TestCase):
    @patch("Scan_nmap_TLS3.socket.gethostbyaddr")
    def test_returns_resolved_fqdn(self, gethostbyaddr):
        gethostbyaddr.return_value = ("host.example.com.", [], ["192.0.2.10"])

        self.assertEqual(scanner.resolve_fqdn("192.0.2.10"), "host.example.com")

    @patch("Scan_nmap_TLS3.socket.gethostbyaddr")
    def test_returns_empty_value_when_reverse_dns_fails(self, gethostbyaddr):
        gethostbyaddr.side_effect = socket.herror

        self.assertEqual(scanner.resolve_fqdn("192.0.2.10"), "")


class ResolveTargetFqdnTests(unittest.TestCase):
    @patch("Scan_nmap_TLS3.socket.gethostbyname_ex")
    def test_maps_target_fqdn_to_its_resolved_ip_addresses(self, gethostbyname_ex):
        gethostbyname_ex.return_value = (
            "smtp.free.fr",
            ["mail.free.fr"],
            ["212.27.48.4", "2001:db8::1"],
        )

        self.assertEqual(
            scanner.resolve_target_fqdns("smtp.free.fr,192.0.2.10,192.0.2.0/24"),
            {
                "212.27.48.4": "smtp.free.fr",
                "2001:db8::1": "smtp.free.fr",
            },
        )


# Per-suite compliance policy and CSV-only reason generation.
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

    def test_accepts_static_rsa_key_exchange(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, "OK")

    def test_accepts_static_rsa_with_cbc_and_sha256(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, "OK")

    def test_returns_short_csv_reason_for_ko(self):
        result = scanner.evaluate_compliance(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "2099-01-01",
            "",
            "RSA",
            1024,
        )

        self.assertEqual(result, ("KO", "RSA key size"))

    def test_returns_empty_csv_reason_for_ok(self):
        result = scanner.evaluate_compliance(
            "TLSv1.2",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, ("OK", ""))

    def test_returns_sha1_reason_for_legacy_sha_suffix(self):
        result = scanner.evaluate_compliance(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "2099-01-01",
            "",
            "RSA",
            3072,
        )

        self.assertEqual(result, ("KO", "SHA-1"))

    def test_accepts_rsa_key_2048_bits(self):
        result = scanner.check_compliance(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "2099-01-01",
            "",
            "RSA",
            2048,
        )

        self.assertEqual(result, "OK")

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

class PQCPrerequisiteTests(unittest.TestCase):
    def test_parses_openssl_version(self):
        self.assertEqual(
            scanner.parse_openssl_version("OpenSSL 3.5.2 5 Aug 2025"),
            (3, 5, 2),
        )

    @patch("Scan_nmap_TLS3.shutil.which", return_value=None)
    def test_rejects_missing_openssl(self, _which):
        with self.assertRaisesRegex(
            scanner.PQCPrerequisiteError,
            "OpenSSL 3.5 or later is required",
        ):
            scanner.check_pqc_prerequisites()

    @patch("Scan_nmap_TLS3.subprocess.run")
    @patch("Scan_nmap_TLS3.shutil.which", return_value="/usr/bin/openssl")
    def test_rejects_openssl_older_than_3_5(self, _which, run):
        run.return_value = Mock(
            returncode=0,
            stdout="OpenSSL 3.4.1 11 Feb 2025\n",
            stderr="",
        )

        with self.assertRaisesRegex(
            scanner.PQCPrerequisiteError,
            "Detected version: OpenSSL 3.4.1",
        ):
            scanner.check_pqc_prerequisites()

        run.assert_called_once()

    @patch("Scan_nmap_TLS3.subprocess.run")
    @patch("Scan_nmap_TLS3.shutil.which", return_value="/usr/bin/openssl")
    def test_accepts_openssl_3_5_with_ml_kem_tls_group(self, _which, run):
        run.side_effect = [
            Mock(
                returncode=0,
                stdout="OpenSSL 3.5.0 8 Apr 2025\n",
                stderr="",
            ),
            Mock(
                returncode=0,
                stdout="X25519MLKEM768\nX25519\n",
                stderr="",
            ),
        ]

        version, groups = scanner.check_pqc_prerequisites()

        self.assertEqual(version, "OpenSSL 3.5.0 8 Apr 2025")
        self.assertEqual(groups, ["X25519MLKEM768"])

    @patch("Scan_nmap_TLS3.load_dependencies")
    @patch("Scan_nmap_TLS3.print_startup_banner")
    @patch("Scan_nmap_TLS3.check_pqc_prerequisites")
    @patch("Scan_nmap_TLS3.parse_args")
    def test_main_stops_before_loading_nmap_when_preflight_fails(
        self,
        parse_args,
        check_prerequisites,
        print_startup_banner,
        load_dependencies,
    ):
        parse_args.return_value = SimpleNamespace(
            crypto="pqc",
            targets="192.0.2.10",
            no_log_file=True,
        )
        check_prerequisites.side_effect = scanner.PQCPrerequisiteError(
            "PQC preflight check failed."
        )

        self.assertEqual(scanner.main(), 2)
        print_startup_banner.assert_called_once_with()
        load_dependencies.assert_not_called()


class PQCComplianceTests(unittest.TestCase):
    def test_accepts_tls_1_3_with_hybrid_ml_kem(self):
        self.assertEqual(
            scanner.evaluate_pqc_compliance("TLSv1.3", "X25519MLKEM768"),
            ("OK", ""),
        )

    def test_rejects_tls_1_2_even_with_hybrid_ml_kem(self):
        self.assertEqual(
            scanner.evaluate_pqc_compliance("TLSv1.2", "X25519MLKEM768"),
            ("KO", "TLS 1.3 required"),
        )

    def test_rejects_tls_1_3_without_supported_pqc_group(self):
        self.assertEqual(
            scanner.evaluate_pqc_compliance("TLSv1.3", "Not supported"),
            ("KO", "No supported PQC group"),
        )

    @patch("Scan_nmap_TLS3.subprocess.run")
    def test_detects_negotiated_hybrid_group(self, run):
        run.return_value = Mock(
            returncode=0,
            stdout="",
            stderr=(
                "CONNECTION ESTABLISHED\n"
                "Protocol version: TLSv1.3\n"
                "Negotiated TLS1.3 group: X25519MLKEM768\n"
            ),
        )

        result = scanner.probe_pqc_key_exchange(
            "192.0.2.10",
            443,
            "host.example",
            ["X25519MLKEM768"],
        )

        self.assertEqual(result, "X25519MLKEM768")
        command = run.call_args.args[0]
        self.assertIn("-tls1_3", command)
        self.assertIn("X25519MLKEM768", command)
        self.assertEqual(command[-2:], ["-servername", "host.example"])


# Parsing of every TLS version and cipher suite returned by Nmap.
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


# Certificate public-key and signature metadata extraction.
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


# Endpoint grades use the weakest finding for each individual host and port.
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

    def test_applies_worst_grade_per_host_and_port(self):
        results = [
            ["192.0.2.10", "host.example", 443, "TLSv1.3"],
            ["192.0.2.10", "host.example", 8443, "TLSv1.2"],
        ]
        findings = {
            ("192.0.2.10", 443): [
                self.finding(),
            ],
            ("192.0.2.10", 8443): [
                self.finding(
                    tls_version="TLSv1.0",
                    cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
                ),
            ]
        }

        scanner.apply_endpoint_grades(results, findings)

        self.assertEqual(results[0][3], "A+")
        self.assertEqual(results[1][3], "D")

    def test_returns_f_for_unknown_tls_version(self):
        finding = self.finding(tls_version="N/A")

        self.assertEqual(scanner.calculate_host_grade([finding]), "F")


if __name__ == "__main__":
    unittest.main()
