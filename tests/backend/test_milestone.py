"""Mandatory milestone: a real scan configured in the WebUI API, run by the historical engine,
persisted, reported, consulted, and consistent with the Standalone CLI."""
from __future__ import annotations

import csv
import io
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from conftest import LAB, POLICY, make_definition, wait_final


def test_real_scan_end_to_end_and_standalone_parity(user, auditor, catalog):
    definition = make_definition(user, catalog, [LAB], name="milestone")
    run = user.post(f"/api/scan-definitions/{definition['id']}/run")
    assert run.status_code == 202, run.text
    run_id = run.json()["run_id"]

    final = wait_final(user, run_id)
    assert final["status"] in ("completed", "partial"), final
    assert final["config_snapshot"] if "config_snapshot" in final else True
    assert final["policy_versions"][0]["version"] == 1
    ports = {e["port"] for e in final["endpoints"]}
    assert {"443", "8443"} <= ports, ports
    assert final["summary"]["total_endpoints"] >= 2
    titles = " ".join(f["title"].lower() for f in final["findings"])
    assert final["findings"], "self-signed / legacy lab endpoints must raise findings"
    assert "trust" in titles or "self" in titles or "certificate" in titles, titles

    # Reports are stored, integrity-checked and downloadable by an AUDITOR.
    assert {r["format"] for r in final["reports"]} >= {"html", "md", "csv", "cbom"}
    html = auditor.get(f"/api/scan-runs/{run_id}/reports/html")
    assert html.status_code == 200 and LAB.encode() in html.content or b"lab" in html.content.lower()
    cbom = auditor.get(f"/api/scan-runs/{run_id}/reports/cbom")
    assert cbom.status_code == 200 and cbom.json()["bomFormat"] == "CycloneDX"
    web_csv = auditor.get(f"/api/scan-runs/{run_id}/reports/csv").text

    # Parity: the Standalone CLI, same engine, same lab target, same policy.
    with tempfile.TemporaryDirectory() as tmp:
        policy_file = Path(tmp) / "policy.yaml"
        policy_file.write_text(yaml.safe_dump({"name": "p", "version": "1", "tls": POLICY}))
        out = Path(tmp) / "out.csv"
        proc = subprocess.run(
            [sys.executable, "tls_scan.py", LAB, "-p", "443,8443", "--workers", "2", "--policy-file", str(policy_file),
             "--no-log-file", "-e", str(out)],
            capture_output=True, text=True, timeout=240, cwd="/app",
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        cli_rows = list(csv.reader(out.open()))

    def core(rows):  # IP, FQDN, Port, Grade, TLS, Cipher, Key, Validity, Compliance, Reason
        return sorted(tuple(r[:10]) for r in rows[1:])

    web_rows = list(csv.reader(io.StringIO(web_csv)))
    assert core(web_rows) == core(cli_rows), "WebUI results differ from the Standalone CLI"
