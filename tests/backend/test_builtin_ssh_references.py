"""LST-38: built-in "SSH Baseline" policy and "Standard (TLS, IPsec, SSH)" generic profile, seeded like ANSSI / Standard."""
from __future__ import annotations

import uuid
from pathlib import Path

import yaml

from conftest import make_user

ROOT = Path(__file__).resolve().parents[2]
# ssh-audit output of a default OpenSSH 10.0p2 (Debian 13), recorded in an isolated lab container.
OPENSSH_10_DEFAULT = {
    "protocol_versions": ["SSH-2.0"],
    "key_exchange": ["mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
                     "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "ext-info-s",
                     "kex-strict-s-v00@openssh.com"],
    "host_key": ["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"],
    "encryption": ["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"],
    "mac": ["umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
            "hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"],
}


def baseline() -> dict:
    return yaml.safe_load((ROOT / "config/encryption_policy/ssh_baseline_policy.yaml").read_text(encoding="utf-8"))["ssh"]


def observation(**algorithms) -> dict:
    return {"status": "observed", "algorithms": {**OPENSSH_10_DEFAULT, **algorithms}, "rsa_key_sizes": [3072]}


def test_baseline_file_is_a_valid_ssh_policy_without_weak_algorithms():
    from orion_app.services.ssh_audit import validate_ssh_policy
    policy = baseline()
    validate_ssh_policy(policy)
    allowed = " ".join(name for key, names in policy.items() if key != "minimum_rsa_bits" for name in names)
    for weak in ("sha1", "-cbc", "3des", "ssh-rsa ", "ssh-dss", "umac-64", "group1-", "group14-sha1", "arcfour"):
        assert weak not in allowed + " ", weak
    assert policy["minimum_rsa_bits"] >= 2048


def test_baseline_on_real_openssh_10_flags_sha1_macs_and_accepts_a_hardened_server():
    from orion_app.services.ssh_audit import evaluate_ssh_policy
    policy = baseline()
    assert evaluate_ssh_policy(observation(), policy) == "non_compliant"           # default MACs still offer hmac-sha1 / umac-64
    hardened_macs = [m for m in OPENSSH_10_DEFAULT["mac"] if "sha1" not in m and "umac-64" not in m]
    assert evaluate_ssh_policy(observation(mac=hardened_macs), policy) == "compliant"   # markers ext-info-s / kex-strict accepted
    assert evaluate_ssh_policy({**observation(mac=hardened_macs), "rsa_key_sizes": [1024]}, policy) == "non_compliant"
    assert evaluate_ssh_policy({"status": "error", "algorithms": {}}, policy) == "indeterminate"   # never compliant without evidence


def test_generic_profile_content_is_valid_and_reuses_the_standard_tls_settings():
    from orion_app.services.bootstrap import GENERIC_IPSEC, GENERIC_SSH
    from orion_app.services.planner import validate_generic_profile_content
    defaults = yaml.safe_load((ROOT / "config/config.yaml").read_text(encoding="utf-8"))["defaults"]
    content = {"tls": {"scan": defaults["scan"], "checks": defaults["checks"]}, "ipsec": {"ike": GENERIC_IPSEC}, "ssh": GENERIC_SSH}
    validate_generic_profile_content(content)


# ---------- seeded and usable through the API (test stack) ----------
def test_references_are_published_at_start_and_allow_a_tls_ssh_definition(admin, catalog):
    ssh = [p for p in admin.get("/api/policies", params={"technology": "ssh"}).json() if p["name"] == "SSH Baseline"]
    generic = [p for p in admin.get("/api/profiles", params={"technology": "generic"}).json() if p["name"] == "Standard (TLS, IPsec, SSH)"]
    assert len(ssh) == 1 and len(generic) == 1
    assert any(v["status"] == "published" for v in ssh[0]["versions"]) and any(v["status"] == "published" for v in generic[0]["versions"])
    user = make_user(admin, "USER")
    target = user.post("/api/targets", json={"value": f"ssh-{uuid.uuid4().hex[:6]}.lab.example", "ports": "22"}).json()
    created = user.post("/api/scan-definitions", json={
        "name": f"tls-ssh-{uuid.uuid4().hex[:6]}", "target_ids": [target["id"]], "profile_id": generic[0]["id"],
        "enabled_controls": ["tls", "ssh"], "control_type": "tls", "policy_ids": [catalog["policy"], ssh[0]["id"]]})
    assert created.status_code in (200, 201), created.text
    assert created.json()["enabled_controls"] == ["tls", "ssh"]
