"""Network map API tests run against the isolated integration Docker stack."""
from __future__ import annotations

import uuid

from conftest import Api, make_definition, wait_final


def test_zone_hierarchy_and_target_membership_are_persistent(operator: Api) -> None:
    suffix = uuid.uuid4().hex[:8]
    si = operator.post("/api/information-systems", json={"name": f"map-si-{suffix}"})
    assert si.status_code == 201, si.text
    child_si = operator.post("/api/information-systems", json={"name": f"map-subsi-{suffix}", "parent_id": si.json()["id"]})
    assert child_si.status_code == 201, child_si.text
    target = operator.post("/api/targets", json={"name": f"map-host-{suffix}", "value": f"map-{suffix}.example.test",
        "si_ids": [si.json()["id"], child_si.json()["id"]]})
    assert target.status_code == 201, target.text
    nested_target = operator.post("/api/targets", json={"name": f"nested-host-{suffix}", "value": f"nested-{suffix}.example.test",
        "si_ids": [child_si.json()["id"]]})
    assert nested_target.status_code == 201, nested_target.text
    unassigned_target = operator.post("/api/targets", json={"name": f"unassigned-host-{suffix}", "value": f"unassigned-{suffix}.example.test",
        "si_ids": [si.json()["id"]]})
    assert unassigned_target.status_code == 201, unassigned_target.text
    group = operator.post("/api/target-groups", json={"name": f"map-group-{suffix}", "target_ids": [nested_target.json()["id"]],
        "si_ids": [si.json()["id"]]})
    assert group.status_code == 201, group.text

    parent = operator.post("/api/map/zones", json={"name": f"map-zone-{suffix}", "zone_type": "dmz", "cidr": "192.0.2.17/24",
        "si_ids": [si.json()["id"]], "target_ids": [target.json()["id"]], "primary_target_ids": [target.json()["id"]]})
    assert parent.status_code == 201, parent.text
    assert parent.json()["cidr"] == "192.0.2.0/24"
    assert parent.json()["target_ids"] == [target.json()["id"]]

    child = operator.post("/api/map/zones", json={"name": f"child-{suffix}", "parent_zone_id": parent.json()["id"],
        "si_ids": [si.json()["id"]], "target_ids": [nested_target.json()["id"]]})
    assert child.status_code == 201, child.text
    cycle = operator.put(f"/api/map/zones/{parent.json()['id']}", json={"name": parent.json()["name"], "parent_zone_id": child.json()["id"]})
    assert cycle.status_code == 422, cycle.text

    graph = operator.get("/api/map/graph", params={"zone_id": parent.json()["id"]})
    assert graph.status_code == 200, graph.text
    host_nodes = [item for item in graph.json()["nodes"] if item["kind"] == "host"]
    assert len(host_nodes) == 1
    assert host_nodes[0]["target_id"] == target.json()["id"]
    assert host_nodes[0]["exposure"] is None  # Unscanned is unknown, never shown as healthy.
    child_node = next(item for item in graph.json()["nodes"] if item["kind"] == "zone")
    assert child_node["exposure"]["targets"] == 1
    assert child_node["exposure"]["unscanned_targets"] == 1
    si_graph = operator.get("/api/map/graph", params={"si_id": si.json()["id"]}).json()
    assert any(item["zone_id"] == parent.json()["id"] for item in si_graph["nodes"])
    assert any(item.get("group_id") == group.json()["id"] for item in si_graph["nodes"])
    assert any(item["kind"] == "unassigned" for item in si_graph["nodes"])
    group_graph = operator.get("/api/map/graph", params={"group_id": group.json()["id"]}).json()
    assert any(item.get("target_id") == nested_target.json()["id"] for item in group_graph["nodes"])
    expanded = operator.get("/api/map/graph", params={"si_id": si.json()["id"], "expand_unassigned": "true"}).json()
    assert any(item.get("target_id") == unassigned_target.json()["id"] for item in expanded["nodes"])

    saved = operator.get("/api/map/zones")
    assert any(item["id"] == child.json()["id"] and item["parent_zone_id"] == parent.json()["id"] for item in saved.json())
    overview = operator.get("/api/map/summary").json()
    system = next(item for item in overview["systems"] if item["id"] == si.json()["id"])
    assert system["exposure"]["targets"] == 3  # Membership in both SI levels remains one target per unique asset.


def test_device_links_validate_addresses_and_keep_provenance(operator: Api) -> None:
    suffix = uuid.uuid4().hex[:8]
    si = operator.post("/api/information-systems", json={"name": f"link-si-{suffix}"})
    assert si.status_code == 201, si.text
    zone = operator.post("/api/map/zones", json={"name": f"link-zone-{suffix}", "zone_type": "dmz", "si_ids": [si.json()["id"]]})
    assert zone.status_code == 201, zone.text
    bad = operator.post("/api/map/devices", json={"name": "bad", "ip_address": "192.0.2.999"})
    assert bad.status_code == 422
    left = operator.post("/api/map/devices", json={"name": f"edge-{suffix}", "device_type": "firewall", "zone_id": zone.json()["id"], "ip_address": "192.0.2.1"})
    right = operator.post("/api/map/devices", json={"name": f"core-{suffix}", "device_type": "router", "zone_id": zone.json()["id"], "ip_address": "192.0.2.2"})
    assert left.status_code == right.status_code == 201

    link = operator.post("/api/map/links", json={"source_device_id": left.json()["id"], "target_device_id": right.json()["id"],
        "provenance": "OBSERVED", "source": "network inventory", "observed_at": "2026-10-14T10:00:00Z", "confidence": 0.9})
    assert link.status_code == 201, link.text
    assert link.json()["provenance"] == "OBSERVED"
    assert link.json()["confidence"] == 0.9
    for params in ({"zone_id": zone.json()["id"], "mode": "network"}, {"si_id": si.json()["id"], "mode": "network"}):
        graph = operator.get("/api/map/graph", params=params)
        assert graph.status_code == 200, graph.text
        device_ids = {item["id"] for item in graph.json()["nodes"] if item["kind"] == "device"}
        assert {f"device:{left.json()['id']}", f"device:{right.json()['id']}"}.issubset(device_ids)
        assert any(item["source_device_id"] == left.json()["id"] and item["target_device_id"] == right.json()["id"]
                   for item in graph.json()["links"])
    duplicate = operator.post("/api/map/links", json={"source_device_id": left.json()["id"], "target_device_id": right.json()["id"]})
    assert duplicate.status_code == 409


def test_map_reads_require_user_and_topology_writes_require_operator(user: Api, auditor: Api) -> None:
    assert user.get("/api/map/summary").status_code == 200
    assert user.post("/api/map/zones", json={"name": f"forbidden-{uuid.uuid4().hex[:8]}"}).status_code == 403
    assert auditor.get("/api/map/summary").status_code == 403


def test_host_map_uses_the_real_latest_tls_run(operator: Api, catalog: dict) -> None:
    definition = make_definition(operator, catalog, ["intranet.acme.local"], name=f"map-real-{uuid.uuid4().hex[:8]}", ports="443")
    queued = operator.post(f"/api/scan-definitions/{definition['id']}/run")
    assert queued.status_code == 202, queued.text
    finished = wait_final(operator, queued.json()["run_id"], timeout=90)
    assert finished["status"] in ("completed", "partial")
    target = next(item for item in operator.get("/api/targets", params={"q": "intranet.acme.local"}).json()
                  if item["value"] == "intranet.acme.local" and item["ports"] == "443")
    detail = operator.get(f"/api/map/hosts/{target['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["scan"]["run_id"] == queued.json()["run_id"]
    assert detail.json()["scan"]["endpoints"]
    other_port = operator.post("/api/targets", json={"name": "same host, different TLS port", "value": "intranet.acme.local", "ports": "8443"})
    assert other_port.status_code == 201, other_port.text
    other_detail = operator.get(f"/api/map/hosts/{other_port.json()['id']}")
    assert other_detail.status_code == 200
    assert other_detail.json()["scan"] is None  # A result from a different target-port identity is not borrowed.
