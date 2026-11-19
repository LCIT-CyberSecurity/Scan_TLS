from __future__ import annotations

import asyncio
import queue
import socket
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from conftest import PROFILE, wait_final
from orion_app.services import quic_scan


def _certificate(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "quic-test.lcit")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName("quic-test.lcit")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / "quic.crt", directory / "quic.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


class QuicTestServer:
    """Small real aioquic listener; it negotiates TLS/QUIC but receives no application request."""

    def __init__(self, directory: Path):
        self.cert, self.key = _certificate(directory)
        self.ready: queue.Queue[int] = queue.Queue()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        async def start():
            configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
            configuration.load_cert_chain(str(self.cert), str(self.key))
            server = await serve("0.0.0.0", 0, configuration=configuration)
            self.ready.put(server._transport.get_extra_info("sockname")[1])
            await asyncio.to_thread(self.stop.wait)
            server.close()
        asyncio.run(start())

    def __enter__(self):
        self.thread.start()
        self.port = self.ready.get(timeout=10)
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=10)


def _config(port: int) -> dict:
    return {"enabled": True, "ports": [port], "timeout_seconds": 3, "retries": 0,
            "max_targets": 2, "max_parallelism": 1, "max_duration_seconds": 8}


def test_quic_settings_are_opt_in_and_bounded():
    assert quic_scan.effective_config({}, None) is None
    assert quic_scan.effective_config({"enabled": True, "ports": [443]}, None)["enabled"] is True
    assert quic_scan.effective_config({"enabled": True}, False) is None
    with pytest.raises(ValueError):
        quic_scan.validate_profile({"enabled": True, "ports": [0]})
    with pytest.raises(ValueError):
        quic_scan.validate_profile({"enabled": True, "timeout_seconds": 11})
    with pytest.raises(ValueError):
        quic_scan.validate_profile({"enabled": True, "unexpected": True})


def test_real_quic_v1_tls13_h3_handshake_on_configured_nonstandard_udp_port(tmp_path):
    with QuicTestServer(tmp_path) as server:
        rows = quic_scan.scan(_config(server.port), [{"targets": ["127.0.0.1"], "ports": "80"}], [])
    assert len(rows) == 1
    row = rows[0]
    assert (row["transport"], row["port"], row["status"]) == ("udp", server.port, "observed"), str(row)
    assert row["tls_version"] == "TLSv1.3"
    assert row["alpn"] == "h3" and row["http3_status"] == "negotiated"
    assert row["quic_version"] and row["cipher_suite"]
    assert row["certificate"] and row["certificate"]["sha256_fingerprint"]
    assert row["source"] == quic_scan.SOURCE


def test_timeout_is_inconclusive_and_tls_policy_is_not_given_a_full_verdict(monkeypatch):
    async def silent(*_args):
        return {"status": "inconclusive", "reason": "No QUIC handshake response before the configured timeout."}
    monkeypatch.setattr(quic_scan, "_probe", silent)
    policy = {"name": "TLS baseline", "content": {"allowed_versions": ["TLSv1.3"], "allowed_cipher_algorithms": ["AES-GCM"]}}
    rows = quic_scan.scan(_config(443), [{"targets": ["silent.example.test"], "ports": "443"}], [policy])
    assert rows[0]["status"] == "inconclusive"
    assert rows[0]["policy_evaluations"][0]["status"] == "not_evaluated"
    assert {c["status"] for c in rows[0]["policy_evaluations"][0]["checks"]} == {"inconclusive", "not_evaluated"}


def test_tls_policy_subset_marks_only_observed_tls13_fields():
    policy = {"name": "TLS baseline", "content": {"allowed_versions": ["TLSv1.3"], "allowed_cipher_algorithms": ["AES-GCM"]}}
    row = {"status": "observed", "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256"}
    result = quic_scan.evaluate_tls_policy_subset(row, [policy])[0]
    assert result["status"] == "not_evaluated"
    assert [check["status"] for check in result["checks"]] == ["compliant", "compliant", "not_evaluated"]


def test_scan_definition_inherits_profile_but_can_override_without_changing_it(user, operator, catalog, tmp_path):
    with QuicTestServer(tmp_path) as server:
        content = {**PROFILE, "scan": {**PROFILE["scan"], "ports": "80", "quic": {
            "enabled": True, "ports": [server.port], "timeout_seconds": 3, "retries": 0,
            "max_targets": 2, "max_parallelism": 1, "max_duration_seconds": 8,
        }}}
        created = operator.post("/api/profiles", json={"name": f"quic-{uuid.uuid4().hex[:8]}", "content": content})
        assert created.status_code == 201, created.text
        assert operator.post(f"/api/profiles/{created.json()['id']}/publish").status_code == 200
        test_host = socket.gethostbyname(socket.gethostname())
        target = user.post("/api/targets", json={"value": test_host, "ports": "80"})
        if target.status_code == 409:
            target_row = next(x for x in user.get("/api/targets", params={"q": test_host}).json() if x["ports"] == "80")
        else:
            assert target.status_code == 201, target.text
            target_row = target.json()
        body = {"name": f"quic-{uuid.uuid4().hex[:8]}", "profile_id": created.json()["id"],
                "target_ids": [target_row["id"]], "policy_ids": [catalog["policy"]]}
        definition = user.post("/api/scan-definitions", json=body)
        assert definition.status_code == 201, definition.text
        assert definition.json()["quic_enabled"] is None
        launched = user.post(f"/api/scan-definitions/{definition.json()['id']}/run")
        assert launched.status_code == 202, launched.text
        final = wait_final(user, launched.json()["run_id"], timeout=60)
        assert final["status"] in {"completed", "partial"}, final
        assert final["control_type"] == "tls"
        assert any(row["status"] == "observed" and row["port"] == server.port for row in final["quic_observations"]), final["quic_observations"]
        assert "quic_csv" in {report["format"] for report in final["reports"]}
        assert final["endpoints"] == []  # UDP QUIC must never be introduced as a TCP/TLS endpoint.
        detail = operator.get(f"/api/results/{final['id']}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["quic_observations"] == final["quic_observations"]
        published = next(item for item in operator.get("/api/profiles?technology=tls").json() if item["id"] == created.json()["id"])
        assert published["versions"][0]["content"]["scan"]["quic"]["enabled"] is True

        overridden = user.post("/api/scan-definitions", json={**body, "name": f"quic-off-{uuid.uuid4().hex[:8]}", "quic_enabled": False})
        assert overridden.status_code == 201, overridden.text
        assert overridden.json()["quic_enabled"] is False
