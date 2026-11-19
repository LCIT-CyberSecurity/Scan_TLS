from __future__ import annotations

import shutil
import subprocess

import pytest

from orion_app.services import planner, service_identification as services
from conftest import LAB, PROFILE, wait_final


def test_parse_nmap_service_xml_marks_observed_and_indeterminate_services():
    payload = """<nmaprun><host><status state='up'/><address addr='192.0.2.5' addrtype='ipv4'/><ports>
    <port protocol='tcp' portid='443'><state state='open'/><service name='https' product='Example' version='1.2' conf='10'/></port>
    <port protocol='tcp' portid='8443'><state state='open'/></port>
    <port protocol='tcp' portid='22'><state state='closed'/></port>
    </ports></host></nmaprun>"""
    rows = services.parse_nmap_xml(payload, "192.0.2.5", [443, 8443])
    assert [(row["port"], row["status"]) for row in rows] == [(443, "observed"), (8443, "indeterminate")]
    assert rows[0]["product"] == "Example"
    assert rows[0]["source"] == services.SOURCE


def test_nmap_command_is_fixed_bounded_and_has_no_scripts():
    args = services._service_args("fast", "192.0.2.5", [443, 8443], "fast", 3, 20)
    assert args[:3] == ["nmap", "-n", "-sV"]
    assert "--version-light" in args
    assert "--max-retries" in args and "0" in args
    assert "--host-timeout" in args and "20s" in args
    assert "--script" not in args
    assert args[-1] == "192.0.2.5"


def test_identification_stays_within_profile_scope_and_open_ports(monkeypatch):
    calls = []
    class Result:
        returncode = 0
        stdout = "<nmaprun><host><address addr='192.0.2.5' addrtype='ipv4'/><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https' conf='8'/></port></ports></host></nmaprun>"
    monkeypatch.setattr(services.subprocess, "run", lambda args, **kwargs: (calls.append(args) or Result()))
    observations, metadata = services.identify_services(
        [{"targets": ["192.0.2.5", "192.0.2.6"], "ports": "fast"}],
        {"enabled": True, "max_targets": 64, "max_services": 200, "timeout_seconds": 5, "max_parallelism": 1},
        open_ports={"192.0.2.5": [443]},
    )
    assert len(calls) == 1 and calls[0][-1] == "192.0.2.5"
    assert "443" in calls[0]
    assert observations[0]["status"] == "probable"
    assert metadata["targets_tested"] == 1


def test_tls_hosts_without_open_ports_are_reported_as_not_tested(monkeypatch):
    monkeypatch.setattr(services.subprocess, "run", lambda *args, **kwargs: pytest.fail("Nmap must not run without observed open ports"))
    observations, _ = services.identify_services(
        [{"targets": ["192.0.2.5"], "ports": "fast"}],
        {"enabled": True, "max_targets": 64, "max_services": 200, "timeout_seconds": 5, "max_parallelism": 1},
        open_ports={},
    )
    assert len(observations) == 1
    assert observations[0]["status"] == "not_tested"


def test_probe_timeout_is_visible_as_indeterminate(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
    monkeypatch.setattr(services.subprocess, "run", timeout)
    observations, metadata = services.identify_services(
        [{"targets": ["192.0.2.5"], "ports": "443"}],
        {"enabled": True, "strategy": "fast", "max_targets": 1, "max_services": 5, "timeout_seconds": 5, "max_parallelism": 1},
    )
    assert metadata["timed_out"] is True
    assert observations[-1]["status"] == "indeterminate"


def test_service_profiles_validate_limits_and_require_a_protocol():
    planner.validate_service_identification_profile({"strategy": "fast"})
    with pytest.raises(ValueError):
        planner.validate_service_identification_profile({"strategy": "detailed", "timeout_seconds": 91})
    with pytest.raises(ValueError):
        planner.validate_generic_profile_content({"service_identification": {"strategy": "fast"}})


def test_docker_image_contains_nmap_service_probes():
    binary = shutil.which("nmap")
    assert binary
    result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 0 and "Nmap" in result.stdout


def test_scan_can_identify_an_http_service_without_a_tls_endpoint(user, operator, catalog):
    import uuid

    settings = {"strategy": "fast", "max_targets": 8, "max_services": 25,
                "timeout_seconds": 15, "max_parallelism": 2}
    content = {**PROFILE, "scan": {**PROFILE["scan"], "ports": "80"}, "service_identification": settings}
    profile = operator.post("/api/profiles", json={"name": f"service-{uuid.uuid4().hex[:6]}", "content": content})
    assert profile.status_code == 201, profile.text
    assert operator.post(f"/api/profiles/{profile.json()['id']}/publish").status_code == 200
    target_response = user.post("/api/targets", json={"value": LAB, "ports": "80"})
    if target_response.status_code == 409:
        target = next(item for item in user.get("/api/targets", params={"q": LAB}).json()
                      if item["value"] == LAB and item["ports"] == "80")
    else:
        assert target_response.status_code == 201, target_response.text
        target = target_response.json()
    payload = {
        "name": f"service-{uuid.uuid4().hex[:6]}", "profile_id": profile.json()["id"],
        "target_ids": [target["id"]], "policy_ids": [catalog["policy"]],
    }
    disabled = user.post("/api/scan-definitions", json=payload)
    assert disabled.status_code == 201 and disabled.json()["service_identification_enabled"] is False
    definition = user.post("/api/scan-definitions", json={**payload, "service_identification_enabled": True})
    assert definition.status_code == 201, definition.text
    final = wait_final(user, user.post(f"/api/scan-definitions/{definition.json()['id']}/run").json()["run_id"])
    detail = user.get(f"/api/scan-runs/{final['id']}")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["endpoints"] == []  # HTTP remains separate from TLS compliance endpoints.
    assert any(row["port"] == 80 and row["source"] == services.SOURCE for row in body["service_observations"])
    assert "service_csv" in {report["format"] for report in body["reports"]}
    host = user.get(f"/api/map/hosts/{target['id']}")
    assert host.status_code == 200, host.text
    assert host.json()["scan"]["services"]
    assert host.json()["scan"]["service_scan_finished_at"]
