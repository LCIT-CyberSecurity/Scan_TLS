"""From a DNS discovery to scans: coverage by existing scans (no double scanning), group + definition creation at import time."""
# Named so that it runs after test_dns_discovery_v2: it creates targets (gitlab, vpn, srv01...) that the V2 tests expect not to exist yet.
from __future__ import annotations

import os
import socket
import uuid

import pytest

from conftest import make_definition, wait_final
from test_dns_discovery_v2 import add, apply, by_fqdn, discover, dns_settings, isolated_operator, results, targets_of  # noqa: F401

LAB_IP = socket.gethostbyname(os.environ.get("TEST_LAB_DNS_HOST", "lab-dns"))   # ns1.client.test points at the lab DNS server itself


def one_target(api, value, ports=""):
    r = api.post("/api/targets", json={"value": value, "ports": ports})
    if r.status_code == 409:
        return next(t for t in api.get("/api/targets", params={"q": value}).json() if t["value"] == value and t["ports"] == ports)
    assert r.status_code == 201, r.text
    return r.json()


def definition_for(api, catalog, target_ids=(), group_ids=(), name=None, **extra):
    r = api.post("/api/scan-definitions", json={"name": name or f"d2s-{uuid.uuid4().hex[:6]}", "target_ids": list(target_ids), "group_ids": list(group_ids),
                                                "policy_ids": [catalog["policy"]], "profile_id": catalog["profile"], **extra})
    assert r.status_code == 201, r.text
    return r.json()


def test_names_already_in_a_scan_are_marked_with_what_covers_them(operator, catalog):
    job = discover(operator, "client.test", methods=["dns", "axfr"])
    direct = one_target(operator, "gitlab.client.test")
    d1 = definition_for(operator, catalog, target_ids=[direct["id"]])
    member = one_target(operator, "vpn.client.test")
    group = operator.post("/api/target-groups", json={"name": f"g-{uuid.uuid4().hex[:6]}", "target_ids": [member["id"]]}).json()
    d2 = definition_for(operator, catalog, group_ids=[group["id"]])
    one_target(operator, "srv01.client.test")   # in the inventory but in no scan
    data = results(operator, job)
    items = by_fqdn(data)
    cov = items["gitlab.client.test"]["coverage"]
    assert cov["covered"] is True and [(d["name"], d["via"]) for d in cov["definitions"]] == [(d1["name"], "target")]
    cov = items["vpn.client.test"]["coverage"]
    assert cov["covered"] is True and cov["definitions"][0]["via"] == "group" and cov["definitions"][0]["group"] == group["name"]
    assert cov["definitions"][0]["id"] == d2["id"]
    assert items["srv01.client.test"]["coverage"]["covered"] is False          # known target, not scanned by anything
    assert items["intranet.client.test"]["coverage"]["covered"] is False
    assert data["covered"] >= 2 and data["recent_scan_days"] == 7


def test_an_address_or_network_target_covers_the_names_that_resolve_into_it(operator, catalog):
    job = discover(operator, "client.test", methods=["dns", "axfr"])
    net = one_target(operator, "10.10.0.0/28")           # srv01 (10.10.0.10) is inside, gitlab (10.10.0.20) is not
    d = definition_for(operator, catalog, target_ids=[net["id"]])
    items = by_fqdn(results(operator, job))
    inside, outside = items["srv01.client.test"]["coverage"], items["gitlab.client.test"]["coverage"]
    assert inside["covered"] is True and inside["shared_address"] == ["10.10.0.0/28"]
    assert inside["definitions"][0]["id"] == d["id"] and inside["definitions"][0]["via"] == "address"
    assert "10.10.0.0/28" not in outside["shared_address"]


def test_a_recent_completed_scan_marks_the_name_with_that_scan(operator, catalog):
    d = make_definition(operator, catalog, [LAB_IP], name=f"recent-{uuid.uuid4().hex[:6]}")
    r = operator.post(f"/api/scan-definitions/{d['id']}/run")
    assert r.status_code == 202, r.text
    run = wait_final(operator, r.json()["run_id"])
    assert run["status"] in ("completed", "partial"), run
    job = discover(operator, "client.test", methods=["dns", "axfr"])
    ns1 = by_fqdn(results(operator, job))["ns1.client.test"]       # ns1 resolves to the lab DNS machine, which was just scanned by address
    assert ns1["ips"] == [LAB_IP]
    assert ns1["coverage"]["recently_scanned"] is True and ns1["coverage"]["last_scan"]["run_id"] == r.json()["run_id"]
    assert ns1["coverage"]["covered"] is True and ns1["coverage"]["shared_address"] == [LAB_IP]


def test_the_recent_window_is_an_administrator_setting(admin):
    current = admin.get("/api/admin/settings").json()["dns_discovery"]
    assert current["recent_scan_days"] == 7
    for bad in (0, 366, "7", True, 2.5):
        r = admin.put("/api/admin/settings/dns_discovery", json={"value": {**current, "recent_scan_days": bad}})
        assert r.status_code == 422, bad
    ok = admin.put("/api/admin/settings/dns_discovery", json={"value": {**current, "recent_scan_days": 30}})
    assert ok.status_code == 200 and admin.get("/api/admin/settings").json()["dns_discovery"]["recent_scan_days"] == 30
    admin.put("/api/admin/settings/dns_discovery", json={"value": current})


def test_import_into_a_group_and_an_existing_definition(operator, catalog):
    job = discover(operator, "client.test", methods=["dns", "axfr"])
    existing = definition_for(operator, catalog, target_ids=[one_target(operator, "gitlab.client.test")["id"]])
    group_name = f"disc-{uuid.uuid4().hex[:6]}"
    names = ["srv01.client.test", "vpn.client.test"]
    before = by_fqdn(results(operator, job))["vpn.client.test"]["coverage"]["definitions_total"]
    plan = apply(operator, job, add(names), group_name=group_name, scan_definition_ids=[existing["id"]], dry_run=True)
    assert plan.status_code == 200, plan.text
    assert plan.json()["definitions"] == [{"id": existing["id"], "name": existing["name"], "action": "add_group", "scheduled": False}]
    assert not [g for g in operator.get("/api/target-groups").json() if g["name"] == group_name]       # a plan changes nothing
    # (targets that already exist only join the group once the business change is confirmed)
    r = apply(operator, job, add(names), group_name=group_name, scan_definition_ids=[existing["id"]], confirm_business_changes=True)
    assert r.status_code == 200 and r.json()["applied"] is True, r.text
    group = next(g for g in operator.get("/api/target-groups").json() if g["name"] == group_name)
    definition = operator.get(f"/api/scan-definitions/{existing['id']}").json()
    assert group["id"] in definition["group_ids"] and definition["target_ids"] == existing["target_ids"]     # added, nothing removed
    # idempotent: the second time nothing is added again
    again = apply(operator, job, add(names), group_id=group["id"], scan_definition_ids=[existing["id"]])
    assert again.status_code == 200 and again.json()["definitions"][0]["action"] == "already"
    assert operator.get(f"/api/scan-definitions/{existing['id']}").json()["group_ids"] == definition["group_ids"]
    # and now the names read as covered
    cov = by_fqdn(results(operator, job))["vpn.client.test"]["coverage"]
    assert cov["covered"] is True and cov["definitions_total"] == before + 1


def test_import_can_create_the_scan_definition_without_launching_it(operator, catalog):
    job = discover(operator, "client.test", methods=["dns", "axfr"])
    group_name, name = f"disc-{uuid.uuid4().hex[:6]}", f"scan-{uuid.uuid4().hex[:6]}"
    body = {"name": name, "profile_id": catalog["profile"], "policy_ids": [catalog["policy"]], "exclusions": ["legacy.client.test"]}
    r = apply(operator, job, add(["vpn.client.test", "gitlab.client.test"]), group_name=group_name, new_definition=body)
    assert r.status_code == 200, r.text
    assert r.json()["definitions"] == [{"id": None, "name": name, "action": "create", "scheduled": False}]
    created = next(d for d in operator.get("/api/scan-definitions").json() if d["name"] == name)
    group = next(g for g in operator.get("/api/target-groups").json() if g["name"] == group_name)
    assert created["group_ids"] == [group["id"]] and created["target_ids"] == [] and created["exclusions"] == ["legacy.client.test"]
    assert created["policy_ids"] == [catalog["policy"]] and created["owner_id"] == operator.user["id"]
    assert operator.get("/api/scan-runs", params={"definition_id": created["id"]}).json() == []      # nothing was launched


def test_a_definition_needs_a_group_and_valid_references(operator, catalog):
    job = discover(operator, "client.test", methods=["dns", "axfr"])
    existing = definition_for(operator, catalog, target_ids=[one_target(operator, "gitlab.client.test")["id"]])
    assert apply(operator, job, add(["vpn.client.test"]), scan_definition_ids=[existing["id"]]).status_code == 422          # no group
    group = f"disc-{uuid.uuid4().hex[:6]}"
    assert apply(operator, job, add(["vpn.client.test"]), group_name=group, scan_definition_ids=[str(uuid.uuid4())]).status_code == 404
    bad = {"name": "x", "profile_id": str(uuid.uuid4()), "policy_ids": [catalog["policy"]]}
    assert apply(operator, job, add(["vpn.client.test"]), group_name=group, new_definition=bad).status_code == 404
    assert apply(operator, job, add(["vpn.client.test"]), group_name=group, new_definition={**bad, "profile_id": catalog["profile"], "exclusions": ["-oN x"]}).status_code == 422
    assert not [g for g in operator.get("/api/target-groups").json() if g["name"] == group]                                 # every failure changed nothing
