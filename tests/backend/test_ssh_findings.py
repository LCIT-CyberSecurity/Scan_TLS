"""SSH policy violations surface as run findings: grouping, severity, dashboard and comparison (LST-42)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from orion_app.database import Base
from orion_app.models import RunFinding, RunSshObservation, ScanDefinition, ScanRun
from orion_app.services import comparison, dashboard, runs
from orion_app.services.ssh_audit import findings_from_observations

ROOT = Path(__file__).resolve().parents[2]
ANSSI_SSH = {"name": "ANSSI SSH", "content": yaml.safe_load(
    (ROOT / "config/encryption_policy/anssi_ssh_encryption_policy.yaml").read_text(encoding="utf-8"))["ssh"]}
NOW = datetime.now(UTC)


def observed(target: str, *, kex=("ecdh-sha2-nistp256",), enc=("aes256-gcm@openssh.com",), mac=("hmac-sha2-256-etm@openssh.com",),
             host_key=("ecdsa-sha2-nistp256",), rsa_sizes=(), port=22) -> dict:
    return {"target": target, "port": port, "status": "observed", "algorithms": {
        "protocol_versions": ["SSH-2.0"], "key_exchange": list(kex), "encryption": list(enc), "mac": list(mac), "host_key": list(host_key)},
        "rsa_key_sizes": list(rsa_sizes)}


def by_id(findings: list[dict]) -> dict[str, dict]:
    return {f["finding_id"]: f for f in findings}


def test_compliant_server_produces_no_finding():
    assert findings_from_observations([observed("192.0.2.1")], [ANSSI_SSH]) == []


def test_default_openssh_splits_weak_offers_from_strong_ones_outside_the_policy():
    findings = by_id(findings_from_observations([observed(
        "192.0.2.1", kex=("sntrup761x25519-sha512", "curve25519-sha256", "ecdh-sha2-nistp256"),
        mac=("umac-64-etm@openssh.com", "hmac-sha1-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"),
        host_key=("ssh-ed25519", "rsa-sha2-512"), rsa_sizes=(3072,))], [ANSSI_SSH]))
    assert set(findings) == {"SSH_KEX_NOT_ALLOWED", "SSH_WEAK_MAC", "SSH_HOST_KEY_NOT_ALLOWED"}
    assert findings["SSH_WEAK_MAC"]["severity"] == "high"
    assert findings["SSH_WEAK_MAC"]["evidence"] == "192.0.2.1:22/tcp: hmac-sha1-etm@openssh.com, umac-64-etm@openssh.com"
    assert findings["SSH_KEX_NOT_ALLOWED"]["severity"] == "medium"
    assert findings["SSH_KEX_NOT_ALLOWED"]["evidence"] == "192.0.2.1:22/tcp: curve25519-sha256, sntrup761x25519-sha512"
    assert findings["SSH_HOST_KEY_NOT_ALLOWED"]["affected_endpoint_ids"] == ["192.0.2.1:22/tcp"]
    assert all(f["category"] == "SSH" and f["status"] == "KO" and "sshd_config" in f["remediation"] for f in findings.values())


@pytest.mark.parametrize(("key", "offer", "finding_id"), [
    ("enc", "aes128-cbc", "SSH_WEAK_CIPHER"), ("enc", "3des-cbc", "SSH_WEAK_CIPHER"),
    ("kex", "diffie-hellman-group14-sha1", "SSH_WEAK_KEX"), ("host_key", "ssh-rsa", "SSH_WEAK_HOST_KEY"),
    ("host_key", "ssh-dss", "SSH_WEAK_HOST_KEY"), ("mac", "hmac-md5", "SSH_WEAK_MAC"),
    ("enc", "aes256-cbc", "SSH_WEAK_CIPHER"), ("host_key", "ssh-ed25519", "SSH_HOST_KEY_NOT_ALLOWED"),
])
def test_known_weak_offers_are_high_and_others_medium(key, offer, finding_id):
    findings = by_id(findings_from_observations([observed("192.0.2.1", **{key: (offer,)})], [ANSSI_SSH]))
    assert list(findings) == [finding_id]
    assert findings[finding_id]["severity"] == ("high" if "WEAK" in finding_id else "medium")


def test_short_rsa_host_key_and_grouping_across_servers():
    findings = by_id(findings_from_observations([
        observed("192.0.2.1", host_key=("rsa-sha2-512",), rsa_sizes=(1024,)),
        observed("192.0.2.2", host_key=("rsa-sha2-512",), rsa_sizes=(1024, 4096), port=2222),
        observed("192.0.2.3", host_key=("rsa-sha2-512",), rsa_sizes=(4096,)),
    ], [ANSSI_SSH]))
    assert list(findings) == ["SSH_RSA_KEY_TOO_SHORT"]
    assert findings["SSH_RSA_KEY_TOO_SHORT"]["severity"] == "high"
    assert findings["SSH_RSA_KEY_TOO_SHORT"]["affected_endpoint_ids"] == ["192.0.2.1:22/tcp", "192.0.2.2:2222/tcp"]


def test_unobserved_servers_never_produce_findings():
    assert findings_from_observations([{"target": "192.0.2.1", "port": 22, "status": "timeout"},
                                       {"target": "192.0.2.2", "port": 22, "status": "error", "algorithms": {}}], [ANSSI_SSH]) == []


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def ssh_run(db, definition_id, observations: list[dict], *, age_days=0) -> ScanRun:
    run = ScanRun(id=uuid.uuid4(), definition_id=definition_id, name="ssh", status="completed", fingerprint="f",
                  config_snapshot={"control_type": "ssh", "ssh": {"policies": [ANSSI_SSH]}, "export_formats": []},
                  policy_versions=[{"name": "ANSSI SSH", "version": 1}], queued_at=NOW - timedelta(days=age_days, minutes=1),
                  finished_at=NOW - timedelta(days=age_days))
    db.add(run)
    db.flush()
    for o in observations:
        db.add(RunSshObservation(run_id=run.id, target=o["target"], port=o["port"], status=o["status"],
                                 verdict="non_compliant", algorithms=o.get("algorithms") or {}))
    for finding in findings_from_observations(observations, [ANSSI_SSH]):
        db.add(RunFinding(run_id=run.id, **finding))
    db.flush()
    return run


def definition(db) -> uuid.UUID:
    d = ScanDefinition(id=uuid.uuid4(), name="ssh", profile_id=uuid.uuid4(), policy_mode="strict_all")
    db.add(d)
    db.flush()
    return d.id


def test_persisted_run_stores_ssh_findings(db, tmp_path):
    run = ScanRun(id=uuid.uuid4(), name="ssh", status="running", fingerprint="f",
                  config_snapshot={"control_type": "ssh", "ssh": {"policies": [ANSSI_SSH]}, "export_formats": []},
                  queued_at=NOW)
    db.add(run)
    db.flush()
    weak = observed("192.0.2.1", enc=("aes128-cbc",))
    runs.persist_results(db, run, {"report_model": {"statistics": {"ssh_observations": 1}}, "ssh_observations": [
        {**weak, "verdict": "non_compliant", "banner": "SSH-2.0-x", "evidence": {}}]}, "completed", tmp_path)
    stored = db.execute(select(RunFinding).where(RunFinding.run_id == run.id)).scalars().all()
    assert [(f.finding_id, f.severity, f.affected_endpoint_ids) for f in stored] == [("SSH_WEAK_CIPHER", "high", ["192.0.2.1:22/tcp"])]


def test_dashboard_counts_high_ssh_findings(db):
    ssh_run(db, definition(db), [observed("192.0.2.1", enc=("aes128-cbc",))])
    posture = dashboard.posture(db, list(db.execute(select(ScanRun)).scalars()))
    assert posture["findings"]["high"] == {"unique": 1, "endpoints": 1}
    assert posture["vigilance"][0]["finding_id"] == "SSH_WEAK_CIPHER"


def test_comparison_marks_ssh_findings_fixed_only_when_the_server_answered_again(db):
    d = definition(db)
    old = ssh_run(db, d, [observed("192.0.2.1", enc=("aes128-cbc",)), observed("192.0.2.2", enc=("aes128-cbc",))], age_days=1)
    new = ssh_run(db, d, [observed("192.0.2.1")])  # fixed on .1; .2 did not answer this time
    result = comparison.compare_runs(db, old, new)
    assert result["fixed"] == [{"finding_id": "SSH_WEAK_CIPHER", "title": "Weak SSH Cipher Offered", "severity": "high",
                                "affected": ["192.0.2.1:22/tcp"]}]
    assert result["not_retested"][0]["affected"] == ["192.0.2.2:22/tcp"]
    assert result["new"] == []
