from __future__ import annotations

import os
import socket
import uuid

from conftest import Api, wait_for


def test_snmpv3_lldp_preview_requires_confirmation_and_applies_idempotently(operator: Api, user: Api) -> None:
    config = operator.get("/api/map/snmp/config")
    assert config.status_code == 200, config.text
    assert config.json()["enabled"] is True
    assert "auth_key" not in config.text and "priv_key" not in config.text
    assert user.get("/api/map/snmp/config").status_code == 403

    before_ids = {item["id"] for item in operator.get("/api/map/devices").json()}
    address = socket.gethostbyname(os.environ.get("TEST_SNMP_HOST", "lab-snmp"))
    target = operator.post("/api/targets", json={"name": "snmp-fixture", "value": address,
        "ports": str(60000 + int(uuid.uuid4().hex[:4], 16) % 5000)})
    assert target.status_code == 201, target.text
    try:
        assert operator.post("/api/map/snmp/discover", json={"target_ids": [target.json()["id"]], "authorized": False}).status_code == 400
        assert user.post("/api/map/snmp/discover", json={"target_ids": [target.json()["id"]], "authorized": True}).status_code == 403
        queued = operator.post("/api/map/snmp/discover", json={"target_ids": [target.json()["id"]], "authorized": True,
            "timeout_seconds": 2, "concurrency": 2})
        assert queued.status_code == 202, queued.text
        discovery_id = queued.json()["id"]

        def completed():
            response = operator.get(f"/api/map/snmp/discover/{discovery_id}")
            assert response.status_code == 200, response.text
            value = response.json()
            return value if value["status"] in ("done", "failed") else None

        result = wait_for(completed, timeout=45)
        assert result["status"] == "done", result
        assert len(result["items"]) == 1
        item = result["items"][0]
        assert item["status"] == "observed", item
        assert item["sys_descr"]
        assert item["interfaces"]
        assert item["neighbors"][0]["local_port"] == "GigabitEthernet0/1"
        assert item["neighbors"][0]["system_name"] == "fixture-edge-switch"
        assert {device["id"] for device in operator.get("/api/map/devices").json()} == before_ids

        applied = operator.post(f"/api/map/snmp/discover/{discovery_id}/apply", json={"item_indexes": [0], "confirm": True})
        assert applied.status_code == 200, applied.text
        assert applied.json()["devices_created"] == 2
        assert applied.json()["links_created"] == 1
        devices = operator.get("/api/map/devices").json()
        created = [device for device in devices if device["id"] not in before_ids]
        assert len(created) == 2
        local = next(device for device in created if device["target_id"] == target.json()["id"])
        assert local["provenance"] == "OBSERVED" and local["source"].startswith("SNMPv3")
        links = operator.get("/api/map/links").json()
        assert any(link["link_type"] == "lldp" and link["provenance"] == "OBSERVED" and link["observed_at"] for link in links)

        repeated = operator.post(f"/api/map/snmp/discover/{discovery_id}/apply", json={"item_indexes": [0], "confirm": True})
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["devices_created"] == repeated.json()["links_created"] == 0
    finally:
        for device in operator.get("/api/map/devices").json():
            if device["id"] not in before_ids:
                operator.delete(f"/api/map/devices/{device['id']}")
        operator.delete(f"/api/targets/{target.json()['id']}")
