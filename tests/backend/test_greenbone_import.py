"""Greenbone GMP/XML import: common normalization, admin boundary, dry-run and idempotence."""
from __future__ import annotations

import sys
import types
from types import SimpleNamespace
from conftest import wait_for

TARGETS = b'''<get_targets_response status="200">
  <target id="target-a"><name>Production</name><comment>Managed by Greenbone</comment>
    <hosts>192.0.2.45, tls-import.example.test</hosts><exclude_hosts>192.0.2.46</exclude_hosts>
    <port_list id="ports-a"><name>Default TCP</name></port_list></target>
</get_targets_response>'''
PORTS = b'''<get_port_lists_response status="200"><port_list id="ports-a"><name>Default TCP</name>
  <port_ranges><port_range><type>TCP</type><start>443</start><end>443</end></port_range>
  <port_range><type>UDP</type><start>53</start><end>53</end></port_range></port_ranges></port_list></get_port_lists_response>'''
TASKS = b'''<get_tasks_response status="200"><task id="task-a"><name>Weekly TLS check</name>
  <target id="target-a"><name>Production</name></target><config id="config-a"><name>Full and fast</name></config>
</task></get_tasks_response>'''


def test_admin_xml_preview_dry_run_and_idempotent_apply(admin, operator, catalog):
    files = [
        ("targets.xml", TARGETS, "application/xml"),
        ("ports.xml", PORTS, "application/xml"),
        ("tasks.xml", TASKS, "application/xml"),
    ]
    response = admin.post("/api/admin/greenbone/xml", files=[("files", item) for item in files])
    assert response.status_code == 201, response.text
    job_id = response.json()["id"]
    preview = admin.get(f"/api/admin/greenbone/imports/{job_id}/preview")
    assert preview.status_code == 200, preview.text
    data = preview.json()
    assert data["summary"]["new"] == 2
    assert {item["value"] for item in data["targets"]} == {"192.0.2.45", "tls-import.example.test"}
    assert {item["ports"] for item in data["targets"]} == {"443"}
    assert len(data["tasks"]) == 1
    definition = {"task_id": "task-a", "profile_id": catalog["profile"], "policy_ids": [catalog["policy"]]}
    dry = admin.post(f"/api/admin/greenbone/imports/{job_id}/apply", json={"dry_run": True, "selected": [0, 1], "definitions": [definition]})
    assert dry.status_code == 200 and dry.json()["dry_run"] is True
    assert admin.get("/api/targets", params={"q": "tls-import.example.test"}).json() == []
    assert operator.get(f"/api/admin/greenbone/imports/{job_id}/preview").status_code == 403
    queued = admin.post(f"/api/admin/greenbone/imports/{job_id}/apply", json={"dry_run": False, "selected": [0, 1], "definitions": [definition]})
    assert queued.status_code == 202, queued.text
    applied = wait_for(lambda: next((job for job in [admin.get(f"/api/admin/greenbone/imports/{job_id}").json()]
                                     if job["status"] in ("done", "failed")), None), timeout=45)
    assert applied["status"] == "done", applied
    assert applied["result"]["applied"]["created"] == 2 and applied["result"]["applied"]["groups_created"] == 1
    assert applied["result"]["applied"]["definitions_created"] == 1
    assert any(item["name"] == "Weekly TLS check" for item in admin.get("/api/scan-definitions").json())
    target = next(item for item in admin.get("/api/targets", params={"q": "tls-import.example.test"}).json() if item["value"] == "tls-import.example.test")
    assert target["ports"] == "443" and "Import OpenVAS" in target["tags"]
    repeated = admin.post(f"/api/admin/greenbone/imports/{job_id}/apply", json={"dry_run": False, "selected": [0, 1], "definitions": [definition]})
    assert repeated.status_code == 202, repeated.text
    result = wait_for(lambda: next((job for job in [admin.get(f"/api/admin/greenbone/imports/{job_id}").json()]
                                    if job["status"] in ("done", "failed")), None), timeout=45)
    assert result["status"] == "done", result
    assert result["result"]["applied"]["created"] == 0 and result["result"]["applied"]["reused"] == 2
    assert result["result"]["applied"]["groups_created"] == 0
    assert result["result"]["applied"]["definitions_created"] == 0 and result["result"]["applied"]["definitions_reused"] == 1
    assert len([item for item in admin.get("/api/targets", params={"q": "tls-import.example.test"}).json() if item["value"] == "tls-import.example.test"]) == 1


def test_xml_parser_rejects_reports_malformed_and_xxe(admin):
    bad_documents = [
        ("report.xml", b"<get_reports_response/>"),
        ("broken.xml", b"<get_targets_response>"),
        ("xxe.xml", b'''<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <get_targets_response><target id="x"><name>&xxe;</name></target></get_targets_response>'''),
    ]
    for filename, payload in bad_documents:
        response = admin.post("/api/admin/greenbone/xml", files={"files": (filename, payload, "application/xml")})
        assert response.status_code == 422, response.text


def test_apply_rejects_out_of_range_selection(admin):
    response = admin.post("/api/admin/greenbone/xml", files={"files": ("empty.xml", b"<get_targets_response/>", "application/xml")})
    assert response.status_code == 201, response.text
    job_id = response.json()["id"]
    result = admin.post(f"/api/admin/greenbone/imports/{job_id}/apply", json={"dry_run": True, "selected": [999]})
    assert result.status_code == 422


def test_target_without_tcp_port_list_is_not_importable(admin):
    target_xml = b'<get_targets_response><target id="no-ports"><name>Example</name><hosts>tls-no-ports.example.test</hosts></target></get_targets_response>'
    uploaded = admin.post("/api/admin/greenbone/xml", files={"files": ("targets.xml", target_xml, "application/xml")})
    assert uploaded.status_code == 201, uploaded.text
    job_id = uploaded.json()["id"]
    target = admin.get(f"/api/admin/greenbone/imports/{job_id}/preview").json()["targets"][0]
    assert target["importable"] is False and target["action"] == "unimportable"
    result = admin.post(f"/api/admin/greenbone/imports/{job_id}/apply", json={"dry_run": False, "selected": [0]})
    assert result.status_code == 422
    assert admin.get("/api/targets", params={"q": "tls-no-ports.example.test"}).json() == []


def test_xml_source_identifier_is_repeatable():
    from tls_scan_app.services.greenbone import normalize_xml

    first = normalize_xml([("targets.xml", TARGETS)])
    again = normalize_xml([("renamed.xml", TARGETS)])
    assert first["source_id"] == again["source_id"]


def test_gmp_reads_all_collections_with_mocked_python_gvm(monkeypatch):
    from tls_scan_app.services import greenbone

    class FakeGMP:
        def __init__(self, **kwargs):
            self.connection = kwargs["connection"]

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def get_version(self):
            return "22.7"

        def authenticate(self, username, password):
            assert (username, password) == ("reader", "protected")

        def _response(self, name, element):
            return greenbone.ET.fromstring(f'<{name}_response><{element} id="sample"><name>Sample</name></{element}></{name}_response>')

        def get_targets(self, **kwargs):
            return self._response("get_targets", "target")

        def get_tasks(self, **kwargs):
            return self._response("get_tasks", "task")

        def get_port_lists(self, **kwargs):
            return self._response("get_port_lists", "port_list")

        def get_scan_configs(self, **kwargs):
            return self._response("get_scan_configs", "config")

        def get_schedules(self, **kwargs):
            return self._response("get_schedules", "schedule")

        def get_tags(self, **kwargs):
            return self._response("get_tags", "tag")

    class FakeTLS:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    modules = {
        "gvm": types.ModuleType("gvm"),
        "gvm.connections": types.ModuleType("gvm.connections"),
        "gvm.protocols": types.ModuleType("gvm.protocols"),
        "gvm.protocols.gmp": types.ModuleType("gvm.protocols.gmp"),
        "gvm.transforms": types.ModuleType("gvm.transforms"),
    }
    modules["gvm.connections"].TLSConnection = FakeTLS
    modules["gvm.protocols.gmp"].GMP = FakeGMP
    modules["gvm.transforms"].EtreeCheckCommandTransform = lambda: object()
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(greenbone.socket, "getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, ("10.20.30.40", 9390))])
    settings = SimpleNamespace(greenbone_allowed_hosts="gvm.internal", greenbone_username="reader", greenbone_password="protected",
                               greenbone_ca_file="/ca.pem", greenbone_client_cert_file="", greenbone_client_key_file="")
    result = greenbone.retrieve_gmp({"host": "gvm.internal", "port": 9390, "timeout": 10, "username": ""}, settings)
    assert result["gmp_version"] == "22.7"
    assert all(len(result[key]) == 1 for key in ("targets", "tasks", "port_lists", "scan_configs", "schedules", "tags"))
    assert result["source_id"] == "gmp:gvm.internal:9390"
