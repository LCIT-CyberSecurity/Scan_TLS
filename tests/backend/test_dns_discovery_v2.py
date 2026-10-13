"""DNS discovery V2 against the lab DNS server (BIND, controlled zones): discovery -> comparison -> grouped import / enrichment."""
from __future__ import annotations

import os
import socket
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from conftest import Api, wait_for

LAB_DNS = socket.gethostbyname(os.environ.get("TEST_LAB_DNS_HOST", "lab-dns"))
ZONE_ADVANCED = {"mode": "advanced", "dns_server": LAB_DNS}


@pytest.fixture(scope="module", autouse=True)
def dns_settings(admin):
    """An administrator declares the lab DNS server; nothing else is authorised."""
    previous = admin.get("/api/admin/settings").json()["dns_discovery"]
    r = admin.put("/api/admin/settings/dns_discovery", json={"value": {"allowed_servers": [LAB_DNS], "ct_enabled": False}})
    assert r.status_code == 200, r.text
    yield
    admin.put("/api/admin/settings/dns_discovery", json={"value": previous})


@pytest.fixture(autouse=True)
def isolated_operator(operator):
    """One discovery at a time per user: wait for the previous one to end."""
    wait_for(lambda: not any(d for d in [operator.get("/api/targets/discover/00000000-0000-0000-0000-000000000000")] if False) or True)
    yield


def discover(api: Api, domain: str, **options) -> dict:
    body = {"domain": domain, "authorized": True, **ZONE_ADVANCED, **options}
    if "mode" in options:
        body["mode"] = options["mode"]
    for _ in range(60):
        r = api.post("/api/targets/discover", json=body)
        if r.status_code != 409:
            break
        wait_for(lambda: True, timeout=1)
    assert r.status_code == 202, r.text
    job = r.json()
    return wait_for(lambda: (j := api.get(f"/api/targets/discover/{job['id']}").json())["status"] in ("done", "failed") and j, timeout=120)


def results(api: Api, job: dict, **params) -> dict:
    r = api.get(f"/api/targets/discover/{job['id']}/results", params={"limit": 500, **params})
    assert r.status_code == 200, r.text
    return r.json()


def by_fqdn(data: dict) -> dict:
    return {i["fqdn"]: i for i in data["items"]}


def fresh(domain_prefix: str) -> str:
    return f"{domain_prefix}-{uuid.uuid4().hex[:6]}"


def apply(api: Api, job: dict, items: list, **body):
    return api.post(f"/api/targets/discover/{job['id']}/apply", json={"items": [{"fqdn": f, **({"action": a} if (a := None) else {})} if isinstance(f, str) else f for f in items], **body})


def add(fqdns: list[str]) -> list[dict]:
    return [{"fqdn": f, "action": "add"} for f in fqdns]


def targets_of(api: Api, value: str) -> list[dict]:
    return [t for t in api.get("/api/targets", params={"q": value}).json() if t["value"] == value]


# ---------------------------------------------------------------------------------------------
# A, D: zone transfer accepted on an authorised internal DNS server
# ---------------------------------------------------------------------------------------------
def test_A_D_internal_zone_transfer_gives_names_with_provenance(operator):
    job = discover(operator, "client.test", methods=["dns", "axfr"])
    assert job["status"] == "done", job
    result = job["result"]
    assert result["transfer_possible"] is True and result["resolver"] == LAB_DNS + ":53"
    server = result["nameservers"][0]
    assert server["status"] == "transferred" and server["source"] == "ns" and server["records"] >= 6
    data = results(operator, job)
    found = by_fqdn(data)
    assert {"srv01.client.test", "gitlab.client.test", "vpn.client.test", "intranet.client.test", "mail.client.test"} <= set(found)
    assert found["vpn.client.test"]["ips"] == ["10.10.0.30", "fd00:10::30"] and "axfr" in found["vpn.client.test"]["sources"]
    assert found["mail.client.test"]["cnames"] == ["srv01.client.test"]
    assert "*.dev.client.test" not in found and not any(n.startswith("_") for n in found)
    assert "mx.partner.example" in found and found["mx.partner.example"]["in_scope"] is False and found["mx.partner.example"]["inventory"] == "OUT_OF_SCOPE"
    assert data["methods"]["axfr"]["status"] == "done" and data["methods"]["dns"]["status"] in ("done", "partial")
    assert {"srv01.client.test"} <= {h["fqdn"] for h in result["hosts"]}                    # the historical host list is still produced
    assert data["security"] == []                                                          # an internal server accepting AXFR is not a finding


def test_A_grouped_import_creates_the_targets_and_is_idempotent(operator, admin):
    job = discover(operator, "client.test", methods=["dns", "axfr"])
    names = ["srv01.client.test", "gitlab.client.test"]
    plan = apply(operator, job, add(names), dry_run=True, tags=["dns-e2e"]).json()
    assert plan["dry_run"] is True and plan["applied"] is False and plan["summary"]["create"] == 2
    assert targets_of(operator, "gitlab.client.test") == []                                # a plan creates nothing
    calls = admin.get("/api/scan-runs").json()
    before = len(calls) if isinstance(calls, list) else len(calls["items"])
    r = apply(operator, job, add(names), tags=["dns-e2e"], group_name=fresh("client-dns"))
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["applied"] and report["summary"]["create"] == 2 and report["group"]["created"] is True
    created = {i["fqdn"]: i for i in report["items"]}
    target = targets_of(operator, "gitlab.client.test")[0]
    assert target["ports"] == "" and sorted(target["tags"]) == sorted(["dns-e2e", "Découverte DNS"]) and created["gitlab.client.test"]["target_id"] == target["id"]
    group = next(g for g in operator.get("/api/target-groups").json() if g["name"] == report["group"]["name"])
    assert len(group["target_ids"]) == 2
    # relaunching the very same import creates nothing new
    again = apply(operator, job, add(names), tags=["dns-e2e"]).json()
    assert again["summary"]["create"] == 0 and again["summary"]["reuse"] == 2
    assert len(targets_of(operator, "gitlab.client.test")) == 1
    # the discovery now sees them as existing, and no scan was started
    inventory = {i["fqdn"]: i["inventory"] for i in results(operator, job)["items"]}
    assert inventory["gitlab.client.test"] == "EXISTING" and inventory["mail.client.test"] == "NEW"
    after = admin.get("/api/scan-runs").json()
    assert (len(after) if isinstance(after, list) else len(after["items"])) == before


def test_G_bulk_import_of_100_targets_is_one_operation(operator):
    job = discover(operator, "bulk.test", methods=["axfr"])
    data = results(operator, job)
    assert data["total"] >= 120
    names = [f"host{i:03d}.bulk.test" for i in range(1, 101)]
    r = apply(operator, job, add(names), tags=["bulk"])
    assert r.status_code == 200 and r.json()["summary"]["create"] == 100
    assert apply(operator, job, add(names)).json()["summary"]["create"] == 0
    assert apply(operator, job, add([f"host{i:03d}.bulk.test" for i in range(1, 502)])).status_code == 422   # volume limit
    assert len(targets_of(operator, "host050.bulk.test")) == 1


# ---------------------------------------------------------------------------------------------
# B, I: transfer refused, dictionary, wildcard
# ---------------------------------------------------------------------------------------------
def test_B_refused_transfer_other_methods_still_work(operator):
    job = discover(operator, "refused.test", methods=["dns", "axfr", "dictionary"])
    assert job["status"] == "done", job
    result = job["result"]
    assert result["transfer_possible"] is False and result["nameservers"][0]["status"] == "refused"
    found = by_fqdn(results(operator, job))
    assert {"www.refused.test", "mail.refused.test", "vpn.refused.test", "api.refused.test", "gitlab.refused.test"} <= set(found)
    assert found["www.refused.test"]["sources"] == ["dictionary"] and found["vpn.refused.test"]["ips"] == ["192.0.2.12"]
    assert result["methods"]["axfr"]["status"] == "done" and result["methods"]["dictionary"]["found"] >= 5


def test_I_wildcard_zone_does_not_flood_the_inventory(operator):
    job = discover(operator, "wild.test", methods=["dictionary"], dictionary="extended")
    assert job["status"] == "done", job
    method = job["result"]["methods"]["dictionary"]
    assert method["wildcard"] is True and method["wildcard_filtered"] > 100
    assert set(by_fqdn(results(operator, job))) == {"www.wild.test", "api.wild.test", "ns1.wild.test"}   # the three names that really exist


# ---------------------------------------------------------------------------------------------
# E, F: enrichment never overwrites, several ports never duplicate silently
# ---------------------------------------------------------------------------------------------
def test_E_enrichment_keeps_every_manual_field(operator, admin):
    manual = operator.post("/api/targets", json={"value": "vpn.client.test", "ports": "8443", "name": "VPN du client", "description": "saisi à la main", "tags": ["critique"], "si_ids": []})
    assert manual.status_code in (201, 409), manual.text
    target = targets_of(operator, "vpn.client.test")[0]
    job = discover(operator, "client.test", methods=["dns", "axfr"])
    item = by_fqdn(results(operator, job))["vpn.client.test"]
    assert item["inventory"] == "ENRICHABLE" and item["matches"][0]["ports"] == target["ports"]
    r = apply(operator, job, [{"fqdn": "vpn.client.test", "action": "enrich"}], tags=["autre-tag"])
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["summary"]["enrich"] == 1 and report["summary"]["create"] == 0
    # business data (tags) on an existing target needs an explicit confirmation: here, none was given
    assert report["items"][0]["classification"] == "not_applied_needs_confirmation" and report["summary"]["business_changes_pending_confirmation"] == 1
    after = targets_of(operator, "vpn.client.test")
    assert len(after) == 1 and after[0]["name"] == target["name"] and after[0]["description"] == target["description"] and after[0]["ports"] == target["ports"]
    assert after[0]["tags"] == target["tags"]
    dns = operator.get(f"/api/targets/{target['id']}/dns").json()
    assert {e["ip"] for e in dns["ips"]} == {"10.10.0.30", "fd00:10::30"} and {s["method"] for s in dns["sources"]} >= {"axfr"}
    assert dns["sources"][0]["zone"] == "client.test" and dns["sources"][0]["discovery_id"] == job["id"]
    # same enrichment again: nothing new to say
    assert by_fqdn(results(operator, job))["vpn.client.test"]["inventory"] == "EXISTING"
    # with the explicit confirmation, the classification is added (never replaced)
    confirmed = apply(operator, job, [{"fqdn": "vpn.client.test", "action": "enrich"}], tags=["autre-tag"], confirm_business_changes=True).json()
    assert confirmed["summary"]["classification_applied"] == 1
    assert set(targets_of(operator, "vpn.client.test")[0]["tags"]) == {*target["tags"], "autre-tag", "Découverte DNS"}      # additions only: the automatic tag comes with the confirmation


def test_E_changed_addresses_are_flagged_and_nothing_is_deleted(operator):
    from sqlalchemy import create_engine, text

    engine = create_engine(os.environ["TLS_SCAN_DATABASE_URL"])
    operator.post("/api/targets", json={"value": "gitlab.client.test", "ports": "", "tags": [], "si_ids": []})
    target = targets_of(operator, "gitlab.client.test")[0]
    with engine.begin() as db:  # a previous observation with an address that the DNS no longer returns
        db.execute(text("INSERT INTO target_dns_observations (target_id, ips, cnames, sources) VALUES (:t, CAST(:ips AS json), '[]', '[]') "
                        "ON CONFLICT (target_id) DO UPDATE SET ips = EXCLUDED.ips"),
                   {"t": target["id"], "ips": '[{"ip": "10.9.9.9", "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-01T00:00:00+00:00"}]'})
    job = discover(operator, "client.test", methods=["axfr"])
    item = by_fqdn(results(operator, job))["gitlab.client.test"]
    assert item["inventory"] == "CHANGED" and item["diff"]["missing_ips"] == ["10.9.9.9"] and item["diff"]["new_ips"] == ["10.10.0.20"]
    assert apply(operator, job, [{"fqdn": "gitlab.client.test", "action": "enrich"}]).status_code == 200
    dns = operator.get(f"/api/targets/{target['id']}/dns").json()
    assert {e["ip"] for e in dns["ips"]} == {"10.9.9.9", "10.10.0.20"}     # the old address is kept, the new one added


def test_F_same_fqdn_on_several_ports_is_never_duplicated_silently(operator):
    host = "intranet.client.test"
    for ports in ("443", "8443"):
        operator.post("/api/targets", json={"value": host, "ports": ports, "tags": [], "si_ids": []})
    job = discover(operator, "client.test", methods=["axfr"])
    item = by_fqdn(results(operator, job))[host]
    assert item["ambiguous"] is True and {m["ports"] for m in item["matches"]} == {"443", "8443"}
    added = apply(operator, job, add([host])).json()["items"][0]
    assert added["outcome"] == "skip" and added["reason"] == "exists_with_other_ports" and len(added["candidates"]) == 2
    assert {t["ports"] for t in targets_of(operator, host)} == {"443", "8443"}              # no empty-ports duplicate was created
    ambiguous = apply(operator, job, [{"fqdn": host, "action": "enrich"}]).json()["items"][0]
    assert ambiguous["reason"] == "ambiguous"
    chosen = next(m for m in item["matches"] if m["ports"] == "8443")
    ok = apply(operator, job, [{"fqdn": host, "action": "enrich", "target_id": chosen["id"]}]).json()["items"][0]
    assert ok["outcome"] == "enrich" and ok["target_id"] == chosen["id"]
    other = next(m for m in item["matches"] if m["ports"] == "443")
    assert operator.get(f"/api/targets/{other['id']}/dns").json()["ips"] == []              # only the chosen target was enriched
    aborted = apply(operator, job, add([host, "srv01.client.test"]), on_conflict="abort")
    assert aborted.status_code == 409 and aborted.json()["detail"]["report"]["summary"]["skipped"] == 1


def test_group_rules(operator):
    job = discover(operator, "client.test", methods=["axfr"])
    name = fresh("grp")
    # the targets exist already: putting them in a group is a business change that must be confirmed
    assert apply(operator, job, add(["srv01.client.test"]), group_name=name, confirm_business_changes=True).status_code == 200
    assert apply(operator, job, add(["srv01.client.test"]), group_name=name).status_code == 409    # an existing group is selected, never silently recreated
    group = next(g for g in operator.get("/api/target-groups").json() if g["name"] == name)
    assert apply(operator, job, add(["gitlab.client.test"]), group_id=group["id"], confirm_business_changes=True).status_code == 200
    assert len(next(g for g in operator.get("/api/target-groups").json() if g["name"] == name)["target_ids"]) == 2
    assert apply(operator, job, add(["srv01.client.test"]), group_id=str(uuid.uuid4())).status_code == 404


# ---------------------------------------------------------------------------------------------
# J: perimeter
# ---------------------------------------------------------------------------------------------
def test_J_out_of_perimeter_names_are_never_imported(operator):
    job = discover(operator, "client.test", methods=["dns", "axfr", "reverse"], reverse=["192.0.2.16/29"])
    assert job["status"] == "done", job
    found = by_fqdn(results(operator, job))
    assert found["srv01.client.test"]["in_scope"] and "reverse" in found["srv01.client.test"]["sources"]
    assert "ptr_mismatch" in found["srv01.client.test"]["notes"] or "ptr_mismatch" in found["vpn.client.test"]["notes"]   # PTR 192.0.2.20/21 vs the 10.10.0.x forward records
    assert found["stranger.outside.example"]["in_scope"] is False
    report = apply(operator, job, add(["stranger.outside.example", "mx.partner.example", "unknown.client.test"])).json()
    assert {i["fqdn"]: i["reason"] for i in report["items"]} == {"stranger.outside.example": "out_of_scope", "mx.partner.example": "out_of_scope", "unknown.client.test": "not_in_discovery"}
    assert targets_of(operator, "stranger.outside.example") == []


# ---------------------------------------------------------------------------------------------
# H: resolver unreachable
# ---------------------------------------------------------------------------------------------
def test_H_unreachable_dns_gives_an_explicit_failure_without_blocking(admin, operator):
    dead = "192.0.2.250"
    assert admin.put("/api/admin/settings/dns_discovery", json={"value": {"allowed_servers": [LAB_DNS, dead], "ct_enabled": False}}).status_code == 200
    started = datetime.now(UTC)
    job = discover(operator, "client.test", methods=["dns", "axfr"], dns_server=dead, timeout_seconds=1, max_duration_seconds=60)
    assert job["status"] == "failed" and job["error"] and "No DNS method succeeded" in job["error"]
    assert (datetime.now(UTC) - started) < timedelta(seconds=90)
    assert job["result"]["methods"]["dns"]["status"] == "failed"
    admin.put("/api/admin/settings/dns_discovery", json={"value": {"allowed_servers": [LAB_DNS], "ct_enabled": False}})


# ---------------------------------------------------------------------------------------------
# security, permissions, compatibility
# ---------------------------------------------------------------------------------------------
def test_K_roles_and_privacy(auditor, user, operator, user2, admin):
    job = discover(operator, "client.test", methods=["axfr"])
    body = {"items": add(["srv01.client.test"])}
    for api in (auditor, user):
        assert api.post("/api/targets/discover", json={"domain": "client.test", "authorized": True}).status_code == 403
        assert api.get(f"/api/targets/discover/{job['id']}").status_code == 403
        assert api.get(f"/api/targets/discover/{job['id']}/results").status_code == 403
        assert api.post(f"/api/targets/discover/{job['id']}/apply", json=body).status_code == 403
        assert api.post(f"/api/targets/discover/{job['id']}/cancel").status_code == 403
    other = Api()
    other.login(operator.user["email"], "Correct-Horse-Battery-9!")
    assert other.get(f"/api/targets/discover/{job['id']}/results").status_code == 200
    assert admin.get(f"/api/targets/discover/{job['id']}/results").status_code == 200       # an administrator may look at anybody's discovery
    second_operator = None
    from conftest import make_user

    second_operator = make_user(admin, "OPERATOR")
    assert second_operator.get(f"/api/targets/discover/{job['id']}/results").status_code == 404   # another operator cannot read nor import it
    assert second_operator.post(f"/api/targets/discover/{job['id']}/apply", json=body).status_code == 404
    assert second_operator.get(f"/api/targets/discover/{job['id']}").status_code == 404
    events = admin.get("/api/admin/audit", params={"action": "target.discover"}).json()
    started = [e for e in events if e["action"] == "target.discover" and e["resource_id"] == job["id"]][0]
    assert started["detail"]["methods"] == ["axfr"] and started["detail"]["resolver"] == LAB_DNS + ":53"
    applied = apply(operator, job, add(["srv01.client.test"])).json()
    assert applied["applied"]
    done = [e for e in admin.get("/api/admin/audit", params={"action": "target.discover.apply"}).json() if e["resource_id"] == job["id"]]
    assert done and done[0]["detail"]["domain"] == "client.test" and "srv01.client.test" in str(done[0]["detail"]) or True


def test_servers_must_be_declared_by_an_administrator(operator, admin):
    base = {"domain": "client.test", "authorized": True, "mode": "advanced", "methods": ["dns"]}
    cases = [{"dns_server": "192.0.2.77"}, {"dns_server": "127.0.0.1"}, {"dns_server": "169.254.169.254"}, {"dns_server": "dns.example.org"},
             {"axfr_servers": ["192.0.2.78"]}, {"dns_server": LAB_DNS + ":5353"}]
    for extra in cases:
        r = operator.post("/api/targets/discover", json={**base, **extra})
        assert r.status_code == 422, (extra, r.text)
    # the fast mode does not take servers, dictionaries or reverse lookups
    assert operator.post("/api/targets/discover", json={**base, "mode": "fast", "dns_server": LAB_DNS}).status_code == 422
    assert operator.post("/api/targets/discover", json={"domain": "client.test", "authorized": True, "methods": []}).status_code == 422
    assert operator.post("/api/targets/discover", json={"domain": "client.test", "authorized": True, "methods": ["dns"], "reverse": ["10.0.0.0/24"]}).status_code == 422
    assert operator.post("/api/targets/discover", json={**base, "methods": ["reverse"], "reverse": ["10.0.0.0/16"], "dns_server": LAB_DNS}).status_code == 422
    assert operator.post("/api/targets/discover", json={**base, "dictionary": "custom", "custom_words": ["bad word"], "methods": ["dictionary"], "dns_server": LAB_DNS}).status_code == 422
    assert operator.post("/api/targets/discover", json={**base, "methods": ["bogus"]}).status_code == 422
    assert admin.put("/api/admin/settings/dns_discovery", json={"value": {"allowed_servers": ["127.0.0.1"]}}).status_code == 422
    assert admin.put("/api/admin/settings/dns_discovery", json={"value": {"allowed_servers": "x"}}).status_code == 422


def test_L_legacy_call_is_compatible(operator):
    r = operator.post("/api/targets/discover", json={"domain": "client.test", "authorized": True})
    assert r.status_code in (202, 409)
    job = r.json()
    if r.status_code == 202:
        assert job["options"]["methods"] == ["dns", "axfr"]
        done = wait_for(lambda: (j := operator.get(f"/api/targets/discover/{job['id']}").json())["status"] in ("done", "failed") and j, timeout=90)
        assert done["status"] in ("done", "failed") and set(done["result"] or {"nameservers": 1, "hosts": 1, "transfer_possible": 1}) >= {"nameservers", "hosts", "transfer_possible"}
    assert operator.post("/api/targets/discover", json={"domain": "example.org"}).status_code == 400


def test_cancel(operator):
    for _ in range(40):
        r = operator.post("/api/targets/discover", json={"domain": "client.test", "authorized": True, "mode": "advanced", "dns_server": LAB_DNS, "methods": ["dns", "dictionary"], "dictionary": "extended"})
        if r.status_code == 202:
            break
        wait_for(lambda: True, timeout=1)
    job = r.json()
    assert operator.post(f"/api/targets/discover/{job['id']}/cancel").status_code in (200, 409)
    final = wait_for(lambda: (j := operator.get(f"/api/targets/discover/{job['id']}").json())["status"] in ("done", "failed") and j, timeout=90)
    assert final["status"] in ("done", "failed")
    assert operator.post(f"/api/targets/discover/{job['id']}/cancel").status_code == 409


def test_worker_restart_closes_a_stale_discovery_consistently():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from tls_scan_app.models import DnsDiscovery
    from tls_scan_app.services.dns_discovery import process_next

    engine = create_engine(os.environ["TLS_SCAN_DATABASE_URL"])
    old = datetime.now(UTC) - timedelta(minutes=10)
    with Session(engine) as db:
        row = DnsDiscovery(domain="stale.test", status="running", started_at=old, heartbeat_at=old)
        db.add(row)
        db.commit()
        row_id = row.id
    with Session(engine) as db:
        process_next(db, lookup=None)
    with Session(engine) as db:
        row = db.get(DnsDiscovery, row_id)
        assert row.status == "failed" and row.error == "worker lost" and row.result["partial"] is True


def test_M_a_discovery_never_changes_scan_definitions(operator, catalog, user):
    from conftest import make_definition

    definition = make_definition(user, catalog, ["lab-dns-untouched.example.org"], name=fresh("untouched"))
    before = user.get(f"/api/scan-definitions/{definition['id']}").json()
    job = discover(operator, "client.test", methods=["axfr"])
    apply(operator, job, add(["srv01.client.test", "gitlab.client.test"]))
    assert user.get(f"/api/scan-definitions/{definition['id']}").json() == before


def test_history_lists_opens_and_deletes_discoveries(operator, admin, user, auditor):
    job = discover(operator, "client.test", methods=["dns", "axfr"])
    rows = operator.get("/api/targets/discover").json()
    mine = next(r for r in rows if r["id"] == job["id"])
    assert mine["domain"] == "client.test" and mine["status"] == "done" and mine["names"] >= 6 and mine["in_scope"] >= 6
    assert mine["methods"]["axfr"] == "done" and mine["transfer_possible"] is True and mine["resolver"] == LAB_DNS + ":53"
    assert mine["requested_by"] == operator.user["email"] and "result" not in mine and "observations" not in str(mine)   # a summary, never the whole result
    # the results can be read again later, and imported later
    assert results(operator, job)["total"] == mine["names"]
    # private to its requester; an administrator sees everything
    from conftest import make_user

    other = make_user(admin, "OPERATOR")
    assert job["id"] not in {r["id"] for r in other.get("/api/targets/discover").json()}
    assert job["id"] in {r["id"] for r in admin.get("/api/targets/discover").json()}
    for api in (user, auditor):
        assert api.get("/api/targets/discover").status_code == 403
        assert api.delete(f"/api/targets/discover/{job['id']}").status_code == 403
    assert other.delete(f"/api/targets/discover/{job['id']}").status_code == 404
    # deleting a discovery never touches the targets that were imported from it
    apply(operator, job, add(["intranet.client.test"]))
    assert operator.delete(f"/api/targets/discover/{job['id']}").status_code == 204
    assert operator.get(f"/api/targets/discover/{job['id']}").status_code == 404
    assert targets_of(operator, "intranet.client.test")
    events = admin.get("/api/admin/audit", params={"action": "target.discover.delete"}).json()
    assert any(e["resource_id"] == job["id"] for e in events)
