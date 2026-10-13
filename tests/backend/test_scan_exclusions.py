"""Scan exclusions: validation, snapshot, global list, and real scans that skip what is excluded."""
from __future__ import annotations

import ipaddress
import socket
import uuid

import pytest

from conftest import LAB, PROFILE, make_definition, wait_final

ACME = "intranet.acme.local"   # alias of the lab server (443 is there too: both names reach the same machine)


def definition_with(api, catalog, targets, exclusions, **extra):
    d = make_definition(api, catalog, targets, name=f"excl-{uuid.uuid4().hex[:6]}")
    body = {"name": d["name"], "target_ids": d["target_ids"], "policy_ids": d["policy_ids"], "profile_id": d["profile_id"], "exclusions": exclusions, **extra}
    r = api.put(f"/api/scan-definitions/{d['id']}", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def run(api, definition):
    r = api.post(f"/api/scan-definitions/{definition['id']}/run")
    assert r.status_code == 202, r.text
    return wait_final(api, r.json()["run_id"])


def test_exclusions_are_validated_and_normalised(user, catalog):
    d = make_definition(user, catalog, [LAB], name=f"excl-{uuid.uuid4().hex[:6]}")
    base = {"name": d["name"], "target_ids": d["target_ids"], "policy_ids": d["policy_ids"], "profile_id": d["profile_id"]}
    ok = user.put(f"/api/scan-definitions/{d['id']}", json={**base, "exclusions": [" 10.0.0.7/24 ", "Legacy.Example.ORG.", "*.Test.example.org"]})
    assert ok.status_code == 200 and ok.json()["exclusions"] == ["10.0.0.0/24", "legacy.example.org", "*.test.example.org"]
    for bad in (["-oN /tmp/x"], ["10.0.0.1 10.0.0.2"], ["*.com"], ["10.0.0.0/40"], [""], ["a,b"]):
        assert user.put(f"/api/scan-definitions/{d['id']}", json={**base, "exclusions": bad}).status_code == 422, bad
    assert user.put(f"/api/scan-definitions/{d['id']}", json={**base, "exclusions": [f"h{i}.example.org" for i in range(501)]}).status_code == 422
    assert user.get(f"/api/scan-definitions/{d['id']}").json()["exclusions"] == ["10.0.0.0/24", "legacy.example.org", "*.test.example.org"]   # failed updates changed nothing
    assert make_definition(user, catalog, [LAB], name=f"excl-{uuid.uuid4().hex[:6]}")["exclusions"] == []                                      # existing behaviour: no exclusion


def test_an_excluded_target_is_not_scanned_and_the_run_says_so(user, catalog):
    d = definition_with(user, catalog, [LAB, ACME], [ACME])
    result = run(user, d)
    assert result["status"] in ("completed", "partial"), result
    assert {e["hostname"] for e in result["endpoints"]} == {LAB}
    assert result["exclusions"]["removed_targets"] == [ACME] and result["exclusions"]["entries"] == [{"value": ACME, "scope": "definition"}]


def test_excluding_a_name_does_not_exclude_the_other_names_of_the_same_address(user, catalog):
    """lab-tls and intranet.acme.local are the same machine: excluding one name must not hide the other."""
    result = run(user, definition_with(user, catalog, [LAB, ACME], [ACME]))
    assert result["endpoints"] and {e["hostname"] for e in result["endpoints"]} == {LAB}


def test_a_wildcard_removes_the_names_below_it(user, catalog):
    d = definition_with(user, catalog, [LAB, ACME], ["*.acme.local"])
    result = run(user, d)
    assert {e["hostname"] for e in result["endpoints"]} == {LAB} and result["exclusions"]["removed_targets"] == [ACME]


def test_nothing_is_excluded_by_default_and_a_scan_without_exclusion_is_unchanged(user, catalog):
    d = make_definition(user, catalog, [LAB, ACME], name=f"excl-{uuid.uuid4().hex[:6]}")
    result = run(user, d)
    assert result["endpoints"] and {e["hostname"] for e in result["endpoints"]} <= {LAB, ACME}   # both names reach one address: one endpoint
    assert result["exclusions"] == {"entries": [], "removed_targets": [], "partial_targets": []}


def test_a_network_is_narrowed_by_nmap_not_dropped(user, catalog):
    ip = socket.gethostbyname(LAB)
    net = str(ipaddress.ip_network(f"{ip}/28", strict=False))
    profile = {**catalog}
    control = run(user, make_definition(user, profile, [net], name=f"excl-{uuid.uuid4().hex[:6]}"))
    assert ip in {e["ip_address"] for e in control["endpoints"]}                    # without exclusion the lab server is found
    narrowed = run(user, definition_with(user, profile, [net], [ip]))
    assert ip not in {e["ip_address"] for e in narrowed["endpoints"]}               # nmap skipped exactly that address
    assert narrowed["exclusions"]["partial_targets"] == [net] and narrowed["exclusions"]["removed_targets"] == []


def test_an_address_resolved_from_a_name_is_excluded_too(user, catalog):
    ip = socket.gethostbyname(LAB)
    result = run(user, definition_with(user, catalog, [LAB, "192.0.2.77"], [ip]))
    assert LAB not in {e["hostname"] for e in result["endpoints"]}


def test_when_everything_is_excluded_the_launch_is_refused(user, catalog):
    d = definition_with(user, catalog, [LAB], [LAB])
    r = user.post(f"/api/scan-definitions/{d['id']}/run")
    assert r.status_code == 422 and "every target is excluded" in r.text


def test_global_exclusions_apply_to_every_definition_and_are_admin_only(admin, operator, user, catalog):
    assert operator.put("/api/admin/settings/scan_exclusions", json={"value": {"entries": [ACME]}}).status_code == 403
    assert admin.put("/api/admin/settings/scan_exclusions", json={"value": {"entries": ["-x"]}}).status_code == 422
    assert admin.put("/api/admin/settings/scan_exclusions", json={"value": {"entries": [ACME.upper()]}}).json() == {"scan_exclusions": {"entries": [ACME]}}
    try:
        assert admin.get("/api/admin/settings").json()["scan_exclusions"]["entries"] == [ACME]
        d = make_definition(user, catalog, [LAB, ACME], name=f"excl-{uuid.uuid4().hex[:6]}")
        result = run(user, d)
        assert {e["hostname"] for e in result["endpoints"]} == {LAB}
        assert result["exclusions"]["entries"] == [{"value": ACME, "scope": "global"}]
        events = admin.get("/api/admin/audit", params={"action": "settings.update"}).json()
        assert any(e["resource_id"] == "scan_exclusions" for e in events)
    finally:
        admin.put("/api/admin/settings/scan_exclusions", json={"value": {"entries": []}})


def test_a_profile_can_carry_exclusions_too(operator, user, catalog):
    content = {**PROFILE, "scan": {**PROFILE["scan"], "exclude": [ACME]}}
    profile = operator.post("/api/profiles", json={"name": f"excl-{uuid.uuid4().hex[:6]}", "content": content})
    assert profile.status_code == 201, profile.text
    assert operator.post(f"/api/profiles/{profile.json()['id']}/publish").status_code == 200
    bad = operator.post("/api/profiles", json={"name": f"excl-{uuid.uuid4().hex[:6]}", "content": {**PROFILE, "scan": {**PROFILE["scan"], "exclude": ["-oN x"]}}})
    assert bad.status_code == 422
    d = make_definition(user, {**catalog, "profile": profile.json()["id"]}, [LAB, ACME], name=f"excl-{uuid.uuid4().hex[:6]}")
    result = run(user, d)
    assert {e["hostname"] for e in result["endpoints"]} == {LAB} and result["exclusions"]["entries"] == [{"value": ACME, "scope": "profile"}]


def test_different_exclusions_are_different_scans(user, catalog):
    """The equivalence check that merges identical scans must not merge a scan with and without exclusion."""
    a = definition_with(user, catalog, [LAB, ACME], [])
    b = definition_with(user, catalog, [LAB, ACME], [ACME])
    ra = user.post(f"/api/scan-definitions/{a['id']}/run").json()
    rb = user.post(f"/api/scan-definitions/{b['id']}/run").json()
    assert ra["run_id"] != rb["run_id"]
    wait_final(user, ra["run_id"])
    wait_final(user, rb["run_id"])
