"""Greenbone is a read-only, target-address import into the Orion inventory."""
from __future__ import annotations

import sys
import types
from types import SimpleNamespace

from conftest import wait_for

TARGETS = b'''<get_targets_response status="200">
  <target id="target-a"><name>Production</name><comment>Managed by Greenbone</comment>
    <hosts>198.51.100.45, tls-import.example.test</hosts><exclude_hosts>192.0.2.46</exclude_hosts>
    <port_list id="ports-a"><name>These ports are ignored</name></port_list></target>
</get_targets_response>'''


def test_admin_xml_preview_dry_run_and_idempotent_import(admin, operator):
    response = admin.post("/api/admin/greenbone/xml", files={"files": ("targets.xml", TARGETS, "application/xml")})
    assert response.status_code == 201, response.text
    job_id = response.json()["id"]
    assert response.json()["result"]["objects"] == {"targets": 1}
    preview = admin.get(f"/api/admin/greenbone/imports/{job_id}/preview")
    assert preview.status_code == 200, preview.text
    data = preview.json()
    assert operator.get(f"/api/admin/greenbone/imports/{job_id}/preview").status_code == 403
    assert data["summary"]["new"] == 2
    assert {item["value"] for item in data["targets"]} == {"198.51.100.45", "tls-import.example.test"}
    assert all(item["action"] == "new" for item in data["targets"])
    assert "tasks" not in data and "port_lists" not in data

    dry = admin.post(f"/api/admin/greenbone/imports/{job_id}/apply", json={"dry_run": True, "selected": [0, 1]})
    assert dry.status_code == 200 and dry.json()["dry_run"] is True
    assert admin.get("/api/targets", params={"q": "tls-import.example.test"}).json() == []
    assert admin.get(f"/api/admin/greenbone/imports/{job_id}/preview").status_code == 200

    queued = admin.post(f"/api/admin/greenbone/imports/{job_id}/apply", json={"dry_run": False, "selected": [0, 1]})
    assert queued.status_code == 202, queued.text
    result = wait_for(lambda: next((job for job in [admin.get(f"/api/admin/greenbone/imports/{job_id}").json()]
                      if job["status"] in ("done", "failed")), None), timeout=45)
    assert result["status"] == "done", result
    assert result["result"]["applied"] == {"created": 2, "reused": 0, "ambiguous": 0}
    for value in ("198.51.100.45", "tls-import.example.test"):
        target = next(item for item in admin.get("/api/targets", params={"q": value}).json() if item["value"] == value)
        assert target["ports"] == ""  # use the Orion profile default, never a Greenbone port list
        assert target["name"] == "Production"
        assert "Import OpenVAS" in target["tags"]

    repeated = admin.post(f"/api/admin/greenbone/imports/{job_id}/apply", json={"dry_run": False, "selected": [0, 1]})
    assert repeated.status_code == 202, repeated.text
    repeated_result = wait_for(lambda: next((job for job in [admin.get(f"/api/admin/greenbone/imports/{job_id}").json()]
                               if job["status"] == "done" and job.get("result", {}).get("applied")), None), timeout=45)
    assert repeated_result["result"]["applied"] == {"created": 0, "reused": 2, "ambiguous": 0}
    assert len([item for item in admin.get("/api/targets", params={"q": "tls-import.example.test"}).json()
                if item["value"] == "tls-import.example.test"]) == 1


def test_existing_address_ignores_openvas_ports_and_preserves_tls_fields(admin):
    si = admin.post("/api/information-systems", json={"name": "gb-preserve-si"}).json()
    created = admin.post("/api/targets", json={"value": "198.51.100.46", "ports": "8443", "name": "Manually managed",
                                                "description": "Keep me", "tags": ["Manual"], "si_ids": [si["id"]]})
    assert created.status_code == 201, created.text
    before = created.json()
    group = admin.post("/api/target-groups", json={"name": "gb-preserve-group", "target_ids": [before["id"]]})
    assert group.status_code == 201, group.text
    xml = b'''<get_targets_response><target id="a-different-openvas-uuid"><name>Greenbone name</name>
      <comment>Greenbone comment</comment><hosts>198.51.100.46</hosts><port_list id="other-port-list"/></target></get_targets_response>'''
    uploaded = admin.post("/api/admin/greenbone/xml", files={"files": ("targets.xml", xml, "application/xml")})
    job_id = uploaded.json()["id"]
    preview = admin.get(f"/api/admin/greenbone/imports/{job_id}/preview").json()
    assert preview["targets"][0]["action"] == "existing"
    assert preview["targets"][0]["value"] == before["value"]
    assert admin.post(f"/api/admin/greenbone/imports/{job_id}/apply", json={"dry_run": False, "selected": [0]}).status_code == 202
    result = wait_for(lambda: next((job for job in [admin.get(f"/api/admin/greenbone/imports/{job_id}").json()]
                      if job["status"] == "done" and job.get("result", {}).get("applied")), None), timeout=45)
    assert result["result"]["applied"] == {"created": 0, "reused": 1, "ambiguous": 0}
    after = next(item for item in admin.get("/api/targets", params={"q": "198.51.100.46"}).json() if item["id"] == before["id"])
    assert {key: after[key] for key in ("name", "description", "ports", "tags", "si_ids")} == {
        key: before[key] for key in ("name", "description", "ports", "tags", "si_ids")}
    assert before["id"] in next(item for item in admin.get("/api/target-groups").json()
                                if item["id"] == group.json()["id"])["target_ids"]


def test_historical_same_address_different_ports_is_ambiguous_not_duplicated(admin):
    for ports in ("443", "8443"):
        response = admin.post("/api/targets", json={"value": "tls-ambiguous.example.test", "ports": ports,
                                                      "name": f"Existing {ports}"})
        assert response.status_code == 201, response.text
    xml = b'<get_targets_response><target id="id"><name>Source</name><hosts>TLS-AMBIGUOUS.example.test.</hosts></target></get_targets_response>'
    uploaded = admin.post("/api/admin/greenbone/xml", files={"files": ("targets.xml", xml, "application/xml")})
    job_id = uploaded.json()["id"]
    preview = admin.get(f"/api/admin/greenbone/imports/{job_id}/preview").json()
    assert preview["targets"][0]["value"] == "tls-ambiguous.example.test"
    assert preview["targets"][0]["action"] == "ambiguous"
    assert preview["summary"]["ambiguous"] == 1
    assert admin.post(f"/api/admin/greenbone/imports/{job_id}/apply", json={"dry_run": False, "selected": [0]}).status_code == 202
    result = wait_for(lambda: next((job for job in [admin.get(f"/api/admin/greenbone/imports/{job_id}").json()]
                      if job["status"] == "done" and job.get("result", {}).get("applied")), None), timeout=45)
    assert result["result"]["applied"] == {"created": 0, "reused": 0, "ambiguous": 1}
    matches = [item for item in admin.get("/api/targets", params={"q": "tls-ambiguous.example.test"}).json()
               if item["value"] == "tls-ambiguous.example.test"]
    assert sorted(item["ports"] for item in matches) == ["443", "8443"]


def test_xml_parser_accepts_targets_without_port_list_and_rejects_other_documents(admin):
    no_ports = b'<get_targets_response><target><name>DNS only</name><hosts>192.0.2.50</hosts></target></get_targets_response>'
    accepted = admin.post("/api/admin/greenbone/xml", files={"files": ("targets.xml", no_ports, "application/xml")})
    assert accepted.status_code == 201, accepted.text
    job_id = accepted.json()["id"]
    target = admin.get(f"/api/admin/greenbone/imports/{job_id}/preview").json()["targets"][0]
    assert target["value"] == "192.0.2.50" and target["action"] == "new"
    for filename, payload in (
        ("tasks.xml", b"<get_tasks_response><task id='x'/></get_tasks_response>"),
        ("report.xml", b"<get_reports_response/>"),
        ("broken.xml", b"<get_targets_response>"),
        ("xxe.xml", b"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><get_targets_response><target><hosts>&xxe;</hosts></target></get_targets_response>"),
    ):
        response = admin.post("/api/admin/greenbone/xml", files={"files": (filename, payload, "application/xml")})
        assert response.status_code == 422, response.text


def test_xml_source_identifier_is_repeatable_and_targets_are_normalized():
    from orion_app.services.greenbone import normalize_xml, normalized_targets

    first = normalize_xml([("targets.xml", TARGETS)])
    changed_export = normalize_xml([("targets.xml", b'<get_targets_response><target><hosts>192.0.2.99</hosts></target></get_targets_response>')])
    renamed_export = normalize_xml([("renamed.xml", TARGETS)])
    assert first["source_id"] == changed_export["source_id"]
    assert first["source_id"] != renamed_export["source_id"]
    assert set(first) == {"source_id", "source_name", "mode", "targets"}
    normalized = normalized_targets({"targets": [
        {"id": "one", "name": "x", "hosts": ["EXAMPLE.TEST.", "192.0.2.10/24", "not a host"]},
        {"id": "two", "name": "y", "hosts": ["192.0.2.10/24"]},
    ]})
    assert [(item["value"], item["kind"], item["ports"]) for item in normalized] == [
        ("example.test", "fqdn", ""), ("192.0.2.0/24", "cidr", ""), ("192.0.2.0/24", "cidr", "")]


def test_source_absence_is_reported_without_inventory_mutation():
    from orion_app.models import GreenboneImport
    from orion_app.services.greenbone import _snapshot_changes

    current = GreenboneImport(id="current", mode="gmp", status="done", snapshot={"source_id": "gmp:greenbone:9390"})
    baseline = GreenboneImport(id="previous", mode="gmp", status="done", snapshot={
        "source_id": "gmp:greenbone:9390",
        "targets": [{"id": "a", "name": "Still here", "hosts": ["192.0.2.1"]},
                    {"id": "b", "name": "Removed upstream", "hosts": ["192.0.2.2"]}],
    })
    current.snapshot = {"source_id": "gmp:greenbone:9390", "targets": [
        {"id": "different-uuid", "name": "Still here", "hosts": ["192.0.2.1"]}],
    }

    class Rows:
        def scalars(self): return iter([baseline])
    class FakeDb:
        def get(self, model, key): return current
        def execute(self, _query): return Rows()

    changes = _snapshot_changes(FakeDb(), {**current.snapshot, "import_id": "current"})
    assert changes["baseline_import_id"] == "previous"
    assert changes["absent"] == [{"type": "target", "id": "192.0.2.2", "name": "Removed upstream"}]
    # This comparison is advisory only; the service has no deletion or disable operation.


def test_gmp_retrieval_and_connection_test_only_call_get_targets(monkeypatch):
    from orion_app.services import greenbone

    class FakeGMP:
        calls = []
        def __init__(self, **kwargs): self.connection = kwargs["connection"]
        def __enter__(self): return self
        def __exit__(self, *_): return None
        def get_version(self): self.calls.append("get_version"); return "22.7"
        def authenticate(self, username, password):
            self.calls.append("authenticate")
            assert (username, password) == ("reader", "protected")
        def get_targets(self, **kwargs):
            self.calls.append("get_targets")
            assert kwargs == {"filter_string": "rows=500 first=1"} or kwargs == {"filter_string": "rows=1 first=1"}
            return greenbone.ET.fromstring('<get_targets_response><target id="source"><name>Example</name><hosts>192.0.2.1</hosts></target></get_targets_response>')

    class FakeTLS:
        def __init__(self, **kwargs): self.kwargs = kwargs

    modules = {name: types.ModuleType(name) for name in (
        "gvm", "gvm.connections", "gvm.protocols", "gvm.protocols.gmp", "gvm.transforms")}
    modules["gvm.connections"].TLSConnection = FakeTLS
    modules["gvm.protocols.gmp"].GMP = FakeGMP
    modules["gvm.transforms"].EtreeCheckCommandTransform = lambda: object()
    for name, module in modules.items(): monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(greenbone.socket, "getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, ("10.20.30.40", 9390))])
    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self, *_): return None
    monkeypatch.setattr(greenbone.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    settings = SimpleNamespace(greenbone_allowed_hosts="gvm.internal", greenbone_username="reader", greenbone_password="protected",
                               greenbone_ca_file="/ca.pem", greenbone_client_cert_file="", greenbone_client_key_file="")
    config = {"host": "gvm.internal", "port": 9390, "timeout": 10, "username": ""}
    result = greenbone.retrieve_gmp(config, settings)
    assert result["gmp_version"] == "22.7" and len(result["targets"]) == 1
    assert set(result) == {"source_id", "source_name", "mode", "gmp_version", "targets"}
    FakeGMP.calls.clear()
    checks = greenbone.test_gmp(config, settings)
    assert checks[4]["status"] == "ok" and checks[5]["status"] == "ok"
    assert FakeGMP.calls.count("get_targets") == 1
    assert not set(FakeGMP.calls) & {"get_tasks", "get_port_lists", "get_scan_configs", "get_schedules", "get_tags"}


def test_gmp_password_write_only_and_replaced(tmp_path, monkeypatch):
    from orion_app.api import greenbone as route
    from orion_app.services import greenbone

    key = tmp_path / "key"
    key.write_text("ab" * 32)
    settings = SimpleNamespace(greenbone_credential_key_file=str(key), greenbone_password="deploy-secret",
                               greenbone_allowed_hosts="gvm.example.test")
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))
    row = SimpleNamespace(value={})
    db = SimpleNamespace(get=lambda *args, **kwargs: row, add=lambda *_: None, commit=lambda: None)
    monkeypatch.setattr(route.audit, "record", lambda *_args, **_kwargs: None)
    assert greenbone.connector_password(db, {}, settings) == "deploy-secret"
    common = {"host": "gvm.example.test", "username": "collector"}
    for password in ("first-secret", "", "replacement-secret"):
        result = route.put_connection(route.ConnectionBody(**common, password=password), request, db, None)
        assert result["password_configured"]
        assert "password" not in result and "encrypted_password" not in result
        assert "secret" not in row.value["encrypted_password"]
        expected = password or "first-secret"
        assert greenbone.connector_password(db, result, settings) == expected


def test_gmp_password_setting_requires_admin(auditor):
    result = auditor.put("/api/admin/greenbone/connection", json={"host": "gvm.example.test", "password": "test-only"})
    assert result.status_code == 403
    assert "test-only" not in result.text
