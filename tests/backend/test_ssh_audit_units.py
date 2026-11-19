from __future__ import annotations

import shutil
import subprocess

import pytest
from types import SimpleNamespace

from tls_scan_app.services.ssh_audit import (
    evaluate_ssh_policy,
    audit_target,
    parse_ssh_audit_json,
    validate_ssh_policy,
    validate_ssh_profile,
)


POLICY = {
    "allowed_protocols": ["SSH-2.0"],
    "allowed_kex": ["curve25519-sha256"],
    "allowed_encryption": ["chacha20-poly1305@openssh.com"],
    "allowed_macs": ["hmac-sha2-256-etm@openssh.com"],
    "allowed_host_keys": ["ssh-ed25519"],
    "minimum_rsa_bits": 2048,
}


def test_ssh_audit_observations_are_normalized_and_compared_without_inference():
    parsed = parse_ssh_audit_json({
        "banner": {"protocol": "SSH-2.0", "software": "OpenSSH_9.8", "raw": "SSH-2.0-OpenSSH_9.8"},
        "kex": {"client_to_server": ["curve25519-sha256"]},
        "enc": {"client_to_server": ["chacha20-poly1305@openssh.com"]},
        "mac": {"client_to_server": ["hmac-sha2-256-etm@openssh.com"]},
        "key": {"server_host_key_algorithms": ["ssh-ed25519"]},
    })
    assert parsed["status"] == "observed"
    assert parsed["banner"] == "SSH-2.0-OpenSSH_9.8"
    assert evaluate_ssh_policy(parsed, POLICY) == "compliant"
    parsed["algorithms"]["encryption"].append("3des-cbc")
    assert evaluate_ssh_policy(parsed, POLICY) == "non_compliant"
    assert evaluate_ssh_policy({"status": "timeout"}, POLICY) == "indeterminate"


def test_ssh_policy_checks_rsa_size_only_when_rsa_is_offered():
    observation = {"status": "observed", "algorithms": {
        "protocol_versions": ["SSH-2.0"], "key_exchange": ["curve25519-sha256"],
        "encryption": ["chacha20-poly1305@openssh.com"], "mac": ["hmac-sha2-256-etm@openssh.com"],
        "host_key": ["rsa-sha2-512"],
    }, "rsa_key_sizes": []}
    rsa_policy = {**POLICY, "allowed_host_keys": ["rsa-sha2-512"]}
    assert evaluate_ssh_policy(observation, rsa_policy) == "indeterminate"
    observation["rsa_key_sizes"] = [1024]
    assert evaluate_ssh_policy(observation, rsa_policy) == "non_compliant"


def test_ssh_profile_and_policy_limits_reject_unbounded_values():
    validate_ssh_profile({"ssh": {"ports": [22], "timeout_seconds": 2, "retries": 1, "preset": "quick", "max_targets": 256}})
    with pytest.raises(ValueError):
        validate_ssh_profile({"ssh": {"ports": [22], "timeout_seconds": 30}})
    with pytest.raises(ValueError):
        validate_ssh_profile({"ssh": {"ports": [22], "retries": 2}})
    validate_ssh_policy(POLICY)
    with pytest.raises(ValueError):
        validate_ssh_policy({**POLICY, "minimum_rsa_bits": 0})


def test_docker_image_contains_ssh_audit_cli():
    binary = shutil.which("ssh-audit")
    assert binary
    result = subprocess.run([binary, "--help"], capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 0
    assert "--json" in result.stdout


def test_audit_invocation_is_bounded_and_never_runs_rate_tests(monkeypatch):
    import tls_scan_app.services.ssh_audit as ssh_audit

    monkeypatch.setattr(ssh_audit.shutil, "which", lambda _: "/usr/bin/ssh-audit")
    calls = []
    monkeypatch.setattr(ssh_audit.subprocess, "run", lambda args, **kwargs: (
        calls.append((args, kwargs)) or SimpleNamespace(returncode=0, stdout='{"banner":"SSH-2.0","kex":["curve25519-sha256"],"enc":["chacha20-poly1305@openssh.com"],"mac":["hmac-sha2-256-etm@openssh.com"],"key":["ssh-ed25519"]}', stderr="")))
    observation = audit_target("example.test", 2222, 3)
    args, kwargs = calls[0]
    assert args == ["/usr/bin/ssh-audit", "--json", "--port", "2222", "--timeout", "3", "--skip-rate-test", "example.test"]
    assert kwargs["timeout"] == 5
    assert observation["status"] == "observed"
