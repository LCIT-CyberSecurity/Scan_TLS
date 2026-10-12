"""Integration of the complementary checks in the engine: opt-in, isolated from grades, visible in the reports."""

import json
import threading
import unittest
from unittest.mock import Mock, patch

from tls_scanner import scanner
from tls_scanner.checks import catalog
from tls_scanner.checks.contracts import FAIL, PASS, CheckResult
from tls_scanner.crypto_policy import apply_endpoint_grades
from tls_scanner.exports.html_report import build_html_report_from_model
from tls_scanner.exports.markdown_report import build_markdown_report_from_model
from tls_scanner.exports.report_model import build_report_model, report_model_to_dict
from tls_scanner.models import ScanJob
from tls_scanner import runner


class FakeScanner:
    def __init__(self, hosts=("192.0.2.10",)):
        self.data = {
            host: {"tcp": {443: {"state": "open", "script": {
                "ssl-cert": "Subject: commonName=www.example.org\nIssuer: commonName=www.example.org\nNot valid after: 2099-01-01T00:00:00",
                "ssl-enum-ciphers": "TLSv1.2:\n  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\nTLSv1.3:\n  TLS_AES_256_GCM_SHA384",
            }}}} for host in hosts
        }

    def all_hosts(self):
        return list(self.data)

    def __getitem__(self, host):
        return self.data[host]


def make_job(**kwargs):
    base = dict(targets="192.0.2.10", ports="443", crypto="standard", ip=True, log_file=None, certificate_trust_enabled=False,
                certificate_revocation_enabled=False)
    base.update(kwargs)
    return ScanJob(**base)


def run_collect(job, cancel_event=None):
    results, findings = [], {}
    scanner.collect_scan_results(FakeScanner(), job, results, findings, {}, cancel_event)
    apply_endpoint_grades(results, findings)
    return results, findings


def fake_results(*statuses):
    return tuple(CheckResult(check_id, status, f"{check_id} {status}", {"note": "</script><b>x</b>"}) for check_id, status in statuses)


class ExecutionTests(unittest.TestCase):
    def test_historical_job_never_runs_a_complementary_check(self):
        with patch.object(scanner, "run_complementary_checks") as run:
            results, _ = run_collect(make_job())
        run.assert_not_called()
        self.assertEqual(len(results), 2)

    def test_selected_checks_receive_the_scan_facts_and_do_not_change_rows_or_grades(self):
        baseline_results, _ = run_collect(make_job())
        job = make_job(tls_checks=("hostname_san", "tls_compression"), tls_checks_timeout_seconds=7, tls_checks_budget_seconds=33,
                       tls_check_requested_names={"192.0.2.10": ("www.example.org",)})
        event = threading.Event()
        with patch.object(scanner, "run_complementary_checks", return_value=fake_results(("hostname_san", PASS))) as run:
            results, _ = run_collect(job, event)
        self.assertEqual(results, baseline_results)  # rows (compliance, reasons, grade) are untouched
        args, kwargs = run.call_args
        self.assertEqual(args[:3], (("hostname_san", "tls_compression"), "192.0.2.10", 443))
        self.assertEqual(kwargs["reference_names"], ("www.example.org",))
        self.assertEqual(kwargs["observed_versions"], ["TLSv1.2", "TLSv1.3"])
        self.assertEqual((kwargs["timeout_seconds"], kwargs["budget_seconds"], kwargs["cancel_event"]), (7, 33, event))
        self.assertEqual(set(job.tls_check_results), {"192.0.2.10:443/tcp"})

    def test_logs_carry_ids_and_statuses_only(self):
        job = make_job(tls_checks=("hostname_san",), scan_run_id="run-1")
        with patch.object(scanner, "run_complementary_checks", return_value=fake_results(("hostname_san", FAIL))), self.assertLogs("tls_scan", "INFO") as logs:
            run_collect(job)
        line = next(record for record in logs.records if "tls_checks" in record.getMessage()).getMessage()
        self.assertIn("endpoint=192.0.2.10:443/tcp hostname_san=FAIL", line)
        self.assertNotIn("script", line)

    def test_a_failing_check_does_not_fail_the_scan(self):
        def boom(context):
            raise RuntimeError("boom")

        specs = tuple(catalog.CheckSpec(s.check_id, s.family, boom, s.recommended) for s in catalog.CATALOG)
        job = make_job(tls_checks=catalog.CHECK_IDS)
        with patch.object(catalog, "CATALOG", specs):
            results, _ = run_collect(job)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.status == "ERROR" for r in job.tls_check_results["192.0.2.10:443/tcp"]))

    def test_requested_names_are_only_resolved_when_the_identity_check_is_selected(self):
        logger = Mock()
        for selected, expected in ((("tls_compression",), 0), (("hostname_san",), 1)):
            job = make_job(tls_checks=selected, ports="443")
            with patch.object(runner, "resolve_requested_names", return_value={"192.0.2.10": ("a.example",)}) as resolve, \
                    patch.object(runner, "resolve_target_fqdns", return_value={}), patch.object(runner, "run_scan_with_progress"), \
                    patch.object(runner, "collect_scan_results"), patch.object(runner, "apply_endpoint_grades"):
                runner.collect_job_results(job, "192.0.2.10", logger, Mock(), Mock())
            self.assertEqual(resolve.call_count, expected)


class ReportTests(unittest.TestCase):
    def models(self, with_checks):
        job = make_job(tls_checks=("hostname_san", "tls_compression") if with_checks else ())
        patcher = patch.object(scanner, "run_complementary_checks", return_value=fake_results(("hostname_san", FAIL), ("tls_compression", PASS)))
        with patcher:
            results, _ = run_collect(job)
        return build_report_model(results, job, "2026-10-12T10:00:00+02:00"), results, job

    def test_historical_model_is_unchanged(self):
        model, _, _ = self.models(False)
        data = report_model_to_dict(model)
        self.assertTrue(all("complementary_checks" not in endpoint for endpoint in data["endpoints"]))
        self.assertNotIn("tlschecks", build_html_report_from_model(model))
        self.assertNotIn("Complementary TLS Checks", build_markdown_report_from_model(model))

    def test_checks_are_added_next_to_findings_without_changing_them(self):
        legacy, _, _ = self.models(False)
        enriched, _, _ = self.models(True)
        legacy_dict, enriched_dict = report_model_to_dict(legacy), report_model_to_dict(enriched)
        for endpoint in enriched_dict["endpoints"]:
            self.assertEqual([c["check_id"] for c in endpoint.pop("complementary_checks")], ["hostname_san", "tls_compression"])
        self.assertEqual(enriched_dict["findings"], legacy_dict["findings"])
        self.assertEqual(enriched_dict["statistics"], legacy_dict["statistics"])
        self.assertEqual([e["overall_grade"] for e in enriched_dict["endpoints"]], [e["overall_grade"] for e in legacy_dict["endpoints"]])
        self.assertEqual(enriched_dict["endpoints"], legacy_dict["endpoints"])

    def test_markdown_and_html_sections(self):
        model, _, _ = self.models(True)
        markdown = build_markdown_report_from_model(model)
        self.assertIn("## Complementary TLS Checks", markdown)
        self.assertIn("| 192.0.2.10:443/tcp | FQDN / SAN identity | FAIL |", markdown)
        html = build_html_report_from_model(model)
        self.assertIn('id="tlschecks"', html)
        data = html.split('<script id="report-data" type="application/json">', 1)[1].split("</script>", 1)[0]
        self.assertEqual(json.loads(data)["endpoints"][0]["complementary_checks"][0]["check_id"], "hostname_san")  # </script> in a value cannot break out
        self.assertNotIn("<b>x</b>", html)

    def test_comparison_columns_of_historical_exports_do_not_move(self):
        _, legacy_rows, _ = self.models(False)
        _, new_rows, _ = self.models(True)
        self.assertEqual(legacy_rows, new_rows)


if __name__ == "__main__":
    unittest.main()
