from __future__ import annotations

import uuid

from conftest import wait_final


def test_ssh_only_scan_uses_ssh_policy_and_separate_results(operator, user):
    suffix = uuid.uuid4().hex[:8]
    policy_content = {
        "allowed_protocols": ["SSH-2.0"],
        "allowed_kex": ["curve25519-sha256"],
        "allowed_encryption": ["chacha20-poly1305@openssh.com"],
        "allowed_macs": ["hmac-sha2-256-etm@openssh.com"],
        "allowed_host_keys": ["ssh-ed25519"],
        "minimum_rsa_bits": 2048,
    }
    policy = operator.post("/api/policies", json={"name": f"SSH {suffix}", "technology": "ssh", "content": policy_content})
    assert policy.status_code == 201, policy.text
    assert operator.post(f"/api/policies/{policy.json()['id']}/publish").status_code == 200

    profile = operator.post("/api/profiles", json={
        "name": f"SSH profile {suffix}", "technology": "generic",
        "content": {"ssh": {"ports": [22], "timeout_seconds": 1, "preset": "quick", "max_targets": 8}},
    })
    assert profile.status_code == 201, profile.text
    assert operator.post(f"/api/profiles/{profile.json()['id']}/publish").status_code == 200

    target = user.post("/api/targets", json={"value": "lab-tls", "ports": "443"})
    assert target.status_code in (201, 409), target.text
    target_id = target.json()["id"] if target.status_code == 201 else next(
        item["id"] for item in user.get("/api/targets", params={"q": "lab-tls"}).json() if item["ports"] == "443")
    definition = user.post("/api/scan-definitions", json={
        "name": f"SSH only {suffix}", "enabled_controls": ["ssh"], "target_ids": [target_id],
        "profile_id": profile.json()["id"], "policy_ids": [policy.json()["id"]],
    })
    assert definition.status_code == 201, definition.text
    started = user.post(f"/api/scan-definitions/{definition.json()['id']}/run")
    assert started.status_code == 202, started.text
    run = wait_final(user, started.json()["run_id"], timeout=30)
    assert run["control_type"] == "ssh"
    assert run["endpoints"] == []
    # lab-tls runs no SSH server: a port nobody answers on is not reported, never as a probe error
    assert run["status"] == "completed", run
    assert run["ssh_observations"] == []
    assert any(report["format"] == "ssh_html" for report in run["reports"])
    public_result = user.get(f"/api/results/{run['id']}")
    assert public_result.status_code == 200, public_result.text
    assert public_result.json()["ssh_observations"] == []
    html_report = user.get(f"/api/scan-runs/{run['id']}/reports/ssh_html", params={"inline": "true"})
    assert html_report.status_code == 200
    assert "SSH audit results" in html_report.text
