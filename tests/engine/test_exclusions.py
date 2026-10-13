"""Exclusions of the engine: parsing, matching, what reaches nmap, and the Standalone configuration."""
import unittest
from unittest.mock import MagicMock, patch

from tls_scanner import runner, scanner
from tls_scanner.config import build_job_from_sections
from tls_scanner.exclusions import Exclusions, parse_entries, parse_entry
from tls_scanner.models import ConfigError


class ParsingTests(unittest.TestCase):
    def test_entries_are_normalised(self):
        self.assertEqual(parse_entries([" 10.0.0.5 ", "10.20.0.7/24", "Legacy.Example.ORG.", "*.Test.example.org", "2001:db8::1", "10.0.0.5"]),
                         ("10.0.0.5", "10.20.0.0/24", "legacy.example.org", "*.test.example.org", "2001:db8::1"))
        self.assertEqual(parse_entries(None), ())

    def test_nothing_that_could_become_an_nmap_option_is_accepted(self):
        for bad in ("", " ", "-iL /etc/passwd", "10.0.0.5 10.0.0.6", "a,b", "*", "*.com", "*.", "10.0.0.0/33", "exa mple.org", "--exclude", 5, None):
            with self.assertRaises(ConfigError, msg=repr(bad)):
                parse_entry(bad)
        with self.assertRaises(ConfigError):
            parse_entries("10.0.0.5")
        with self.assertRaises(ConfigError):
            parse_entries(["10.0.0.%d" % (i % 250) for i in range(600)] + [f"h{i}.example.org" for i in range(600)])


class MatchingTests(unittest.TestCase):
    def setUp(self):
        self.ex = Exclusions(parse_entries(["10.0.0.5", "10.20.0.0/24", "legacy.example.org", "*.test.example.org", "2001:db8::/32"]))

    def test_addresses_and_networks(self):
        self.assertTrue(self.ex.ip_excluded("10.0.0.5"))
        self.assertTrue(self.ex.ip_excluded("10.20.0.200"))
        self.assertTrue(self.ex.ip_excluded("2001:db8::99"))
        self.assertFalse(self.ex.ip_excluded("10.0.0.6"))
        self.assertFalse(self.ex.ip_excluded("10.21.0.1"))
        self.assertFalse(self.ex.ip_excluded("not an ip"))

    def test_names_and_wildcards(self):
        self.assertTrue(self.ex.name_excluded("legacy.example.org"))
        self.assertTrue(self.ex.name_excluded("LEGACY.example.org."))
        self.assertTrue(self.ex.name_excluded("a.test.example.org"))
        self.assertTrue(self.ex.name_excluded("a.b.test.example.org"))
        self.assertFalse(self.ex.name_excluded("test.example.org"))        # a wildcard covers what is below, not the apex
        self.assertFalse(self.ex.name_excluded("nottest.example.org"))
        self.assertFalse(self.ex.name_excluded("sub.legacy.example.org"))  # an exact name is exact
        self.assertFalse(self.ex.name_excluded(""))

    def test_targets_are_dropped_kept_or_narrowed(self):
        kept, removed, partial = self.ex.filter_targets(["10.0.0.5", "10.0.0.6", "10.20.0.0/25", "10.0.0.0/24", "10.30.0.0/24", "legacy.example.org", "www.example.org", "x.test.example.org"])
        self.assertEqual(removed, ["10.0.0.5", "10.20.0.0/25", "legacy.example.org", "x.test.example.org"])
        self.assertEqual(kept, ["10.0.0.6", "10.0.0.0/24", "10.30.0.0/24", "www.example.org"])
        self.assertEqual(partial, ["10.0.0.0/24"])                         # contains 10.0.0.5: nmap skips that address

    def test_nmap_argument_has_addresses_and_networks_only(self):
        # a name would exclude the address it resolves to, and with it every other name served there
        self.assertEqual(self.ex.nmap_argument(), "10.0.0.5/32,10.20.0.0/24,2001:db8::/32")
        self.assertEqual(Exclusions(()).nmap_argument(), "")
        self.assertFalse(Exclusions(()))


class EngineTests(unittest.TestCase):
    def test_discovery_passes_exclude_to_nmap_and_nothing_else_changes_without_it(self):
        nmap = MagicMock()
        calls = []
        with patch.object(scanner, "run_scan_with_progress", side_effect=lambda *a, **k: calls.append(k)):
            nmap.PortScanner.return_value.all_hosts.return_value = []
            scanner.discover_open_tcp_ports(nmap, MagicMock(), "10.0.0.0/24", "fast")
            scanner.discover_open_tcp_ports(nmap, MagicMock(), "10.0.0.0/24", "all", "10.0.0.5/32,10.0.0.9/32")
        self.assertEqual(calls[0]["arguments"], "--top-ports 2000 -T4 --open --max-retries 2")   # historical behaviour, byte for byte
        self.assertEqual(calls[1]["arguments"], "-T4 --open --max-retries 1 --exclude 10.0.0.5/32,10.0.0.9/32")
        self.assertEqual(calls[1]["ports"], "1-65535")

    def test_hosts_matching_by_ip_or_name_are_dropped_after_discovery(self):
        job = build_job_from_sections({"ports": "fast", "exclude": ["10.0.0.5", "*.corp.example.org"]}, {}, {}, ["10.0.0.0/29"])
        self.assertEqual(job.exclude, ("10.0.0.5", "*.corp.example.org"))
        seen = {}

        def fake_parallel(nmap, tqdm, open_ports, job_, cache, args, logger, **kwargs):
            seen.update(open_ports)
            return [], {}

        discovered = {"10.0.0.5": [443], "10.0.0.6": [443], "10.0.0.7": [443]}
        with patch.object(runner, "discover_open_tcp_ports", return_value=dict(discovered)) as discover, \
                patch.object(runner, "scan_tls_hosts_parallel", side_effect=fake_parallel), \
                patch.object(runner, "resolve_target_fqdns", return_value={"10.0.0.7": "app.corp.example.org"}), \
                patch.object(runner, "apply_endpoint_grades"):
            runner.collect_job_results(job, "10.0.0.0/29", MagicMock(), MagicMock(), MagicMock())
        self.assertEqual(discover.call_args.args[4], "10.0.0.5/32")
        self.assertEqual(seen, {"10.0.0.6": [443]})                          # .5 by address, .7 by its name

    def test_a_scan_whose_targets_are_all_excluded_is_refused(self):
        job = build_job_from_sections({"ports": "443", "exclude": ["10.0.0.0/24", "x.example.org"]}, {}, {}, ["10.0.0.5", "x.example.org"])
        with patch.dict("sys.modules", {"nmap": MagicMock()}), self.assertRaisesRegex(ConfigError, "every target is excluded"):
            runner.execute_scan(job)

    def test_configuration_is_validated_and_defaults_to_nothing(self):
        self.assertEqual(build_job_from_sections({"ports": "fast"}, {}, {}, ["10.0.0.1"]).exclude, ())
        for bad in ("10.0.0.1", ["-oN x"], [""], [3]):
            with self.assertRaises(ConfigError):
                build_job_from_sections({"ports": "fast", "exclude": bad}, {}, {}, ["10.0.0.1"])


if __name__ == "__main__":
    unittest.main()
