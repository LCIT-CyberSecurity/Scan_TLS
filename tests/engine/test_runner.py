"""Tests of the headless engine interface (tls_scanner.runner). Run: python -m unittest discover tests/engine"""

import threading
import unittest
from unittest.mock import patch

from tls_scanner.models import ConfigError, ScanJob
from tls_scanner.runner import collect_job_results, validate_scan_input
import logging


def job(targets="192.0.2.10,example.org,10.0.0.0/24", ports="443"):
    return ScanJob(targets=targets, ports=ports, crypto="standard", ip=True, log_file=None)


class ValidateScanInputTests(unittest.TestCase):
    def test_accepts_fqdn_ip_cidr(self):
        validate_scan_input(job())
        validate_scan_input(job("2001:db8::1", "80,443,8000-8100"))
        validate_scan_input(job("host_1.example.org", "fast"))

    def test_rejects_option_injection(self):
        for bad in ("-oN /tmp/x", "192.0.2.1 -iL /etc/passwd", "a;b", "$(id)", "a b|c", "--script=x", "-"):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                validate_scan_input(job(bad))

    def test_rejects_bad_ports(self):
        for bad in ("443;ls", "-p-", "443 --open", ""):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                validate_scan_input(job(ports=bad))

    def test_rejects_empty_and_too_many(self):
        with self.assertRaises(ConfigError):
            validate_scan_input(job(" , "))
        with self.assertRaises(ConfigError):
            validate_scan_input(job(",".join(f"h{i}.example.org" for i in range(5000))))


class CancellationTests(unittest.TestCase):
    def test_cancel_skips_unstarted_hosts_and_keeps_partial_results(self):
        cancel = threading.Event()
        done = []

        def fake_scan(nmap, tqdm, host, ports, j, cache, args):
            if host == "10.0.0.1":
                cancel.set()
            return [[host]], {host: 1}

        with patch("tls_scanner.runner.discover_open_tcp_ports", return_value={"10.0.0.1": [443], "10.0.0.2": [443]}), \
             patch("tls_scanner.runner.resolve_target_fqdns", return_value={}), \
             patch("tls_scanner.scanner.scan_tls_host", side_effect=fake_scan), \
             patch("tls_scanner.runner.apply_endpoint_grades"):
            j = job("10.0.0.1 10.0.0.2", "fast")
            j.workers = 1
            results, _ = collect_job_results(
                j, "10.0.0.1 10.0.0.2", logging.getLogger("t"), None, None,
                cancel_event=cancel, on_host_done=lambda h, ok: done.append((h, ok)),
            )
        self.assertEqual(results, [["10.0.0.1"]])
        self.assertEqual(done, [("10.0.0.1", True), ("10.0.0.2", False)])


if __name__ == "__main__":
    unittest.main()
