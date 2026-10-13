"""Discovery -> Targets, made simple: automatic "Découverte DNS" tag, one group per domain, provenance and the targets of an import."""
# Named so that it runs after test_dns_discovery_v2: the targets used here are forgotten first, so the file can be re-run on a used database.
from __future__ import annotations

import uuid

import pytest

from conftest import Api
from test_dns_discovery_v2 import add, apply, by_fqdn, discover, dns_settings, isolated_operator, results, targets_of  # noqa: F401

TAG = "Découverte DNS"


def host(i: int) -> str:
    return f"host{i:03d}.bulk.test"


def forget(api: Api, fqdns: list[str]) -> None:
    wanted = set(fqdns)
    for t in api.get("/api/targets", params={"provenance": "dns"}).json() + api.get("/api/targets", params={"q": "bulk.test"}).json():
        if t["value"] in wanted:
            api.delete(f"/api/targets/{t['id']}")


def tag_names(api: Api) -> list[str]:
    return [t["name"] for t in api.get("/api/tags").json()]


def groups_named(api: Api, name: str) -> list[dict]:
    return [g for g in api.get("/api/target-groups").json() if g["name"] == name]


@pytest.fixture(scope="module")
def job(operator):
    return discover(operator, "bulk.test", methods=["axfr"])


def test_new_targets_get_the_discovery_tag_once(operator, job):
    names = [host(i) for i in range(201, 206)]
    forget(operator, names)
    plan = apply(operator, job, add(names[:3]), dry_run=True).json()
    assert plan["tag"] == TAG and plan["discovery_id"] == job["id"]
    assert all(not targets_of(operator, n) for n in names)                      # a plan creates nothing, tag included
    r = apply(operator, job, add(names[:3]), tags=["extra-tag"])
    assert r.status_code == 200 and r.json()["summary"]["create"] == 3
    for n in names[:3]:
        assert sorted(targets_of(operator, n)[0]["tags"]) == sorted([TAG, "extra-tag"])
    # a second import reuses the same tag: no duplicate, on the targets or in the tag list
    assert apply(operator, job, add(names[3:])).status_code == 200
    assert targets_of(operator, names[4])[0]["tags"] == [TAG]
    assert tag_names(operator).count(TAG) == 1
    again = apply(operator, job, add(names), tags=["extra-tag"], confirm_business_changes=True).json()
    assert again["summary"]["create"] == 0 and again["summary"]["reuse"] == 5
    assert targets_of(operator, names[0])[0]["tags"].count(TAG) == 1


def test_the_automatic_tag_can_be_turned_off(operator, job):
    names = [host(i) for i in range(211, 214)]
    forget(operator, names)
    r = apply(operator, job, add(names), discovery_tag=False)
    assert r.status_code == 200 and r.json()["tag"] is None
    assert all(targets_of(operator, n)[0]["tags"] == [] for n in names)
    assert all(targets_of(operator, n)[0]["dns"] for n in names)                  # the provenance does not depend on the tag


def test_an_existing_target_only_gets_the_tag_after_confirmation_and_keeps_its_data(operator, job):
    name = host(221)
    forget(operator, [name])
    made = operator.post("/api/targets", json={"value": name, "name": "Manual name", "description": "hand written", "tags": ["mine"]})
    assert made.status_code == 201
    plan = apply(operator, job, [{"fqdn": name, "action": "enrich"}], dry_run=True).json()
    assert plan["summary"]["business_changes_pending_confirmation"] == 1
    assert plan["items"][0]["business_changes"]["tags_added"] == [TAG]
    r = apply(operator, job, [{"fqdn": name, "action": "enrich"}]).json()
    assert r["items"][0]["classification"] == "not_applied_needs_confirmation"
    t = targets_of(operator, name)[0]
    assert t["tags"] == ["mine"] and t["name"] == "Manual name" and t["description"] == "hand written"
    assert t["dns"] is not None and t["dns"]["created"] is False                    # enriched, not created
    ok = apply(operator, job, [{"fqdn": name, "action": "enrich"}], confirm_business_changes=True).json()
    assert ok["summary"]["classification_applied"] == 1
    t = targets_of(operator, name)[0]
    assert sorted(t["tags"]) == sorted(["mine", TAG]) and t["name"] == "Manual name" and t["description"] == "hand written"
    # tags are never removed: importing again without the automatic tag keeps both
    apply(operator, job, [{"fqdn": name, "action": "enrich"}], discovery_tag=False, confirm_business_changes=True)
    assert sorted(targets_of(operator, name)[0]["tags"]) == sorted(["mine", TAG])


def test_the_group_of_a_domain_is_proposed_then_reused_by_the_next_discovery(operator, job):
    first, second = [host(i) for i in range(231, 234)], [host(i) for i in range(234, 237)]
    forget(operator, first + second)
    data = results(operator, job)
    proposal = data["default_group"]
    assert proposal["name"] == "DNS — bulk.test" and data["discovery_tag"] == TAG
    for g in groups_named(operator, proposal["name"]):                          # start from a clean state on a re-run
        operator.delete(f"/api/target-groups/{g['id']}")
    assert results(operator, job)["default_group"]["exists"] is False
    r = apply(operator, job, add(first), group_name=proposal["name"], reuse_group=True)
    assert r.status_code == 200 and r.json()["group"]["created"] is True
    group_id = r.json()["group"]["id"]
    assert not any(ch.isdigit() for ch in proposal["name"])                       # no date in the proposed name
    seen = results(operator, job)["default_group"]
    assert seen == {"name": proposal["name"], "id": group_id, "exists": True}
    # another discovery of the same domain feeds the same group: nothing is created twice
    other = discover(operator, "bulk.test", methods=["axfr"])
    r = apply(operator, other, add(second), group_name=proposal["name"], reuse_group=True)
    assert r.status_code == 200 and r.json()["group"]["id"] == group_id and not r.json()["group"].get("created")
    groups = groups_named(operator, proposal["name"])
    assert len(groups) == 1 and set(groups[0]["target_ids"]) == {targets_of(operator, n)[0]["id"] for n in first + second}
    # without the explicit reuse the API still refuses to recreate an existing name
    assert apply(operator, other, add(second), group_name=proposal["name"]).status_code == 409


def test_importing_without_a_group_leaves_the_targets_ungrouped(operator, job):
    names = [host(i) for i in range(241, 243)]
    forget(operator, names)
    before = {g["id"]: len(g["target_ids"]) for g in operator.get("/api/target-groups").json()}
    assert apply(operator, job, add(names)).status_code == 200
    assert {g["id"]: len(g["target_ids"]) for g in operator.get("/api/target-groups").json()} == before


def test_an_existing_target_joins_the_group_only_after_confirmation(operator, job):
    name = host(251)
    forget(operator, [name])
    operator.post("/api/targets", json={"value": name})
    group = operator.post("/api/target-groups", json={"name": f"ux-{uuid.uuid4().hex[:6]}", "target_ids": []}).json()
    plan = apply(operator, job, [{"fqdn": name, "action": "enrich"}], group_id=group["id"], discovery_tag=False).json()
    assert plan["items"][0]["classification"] == "not_applied_needs_confirmation"
    assert next(g for g in operator.get("/api/target-groups").json() if g["id"] == group["id"])["target_ids"] == []
    apply(operator, job, [{"fqdn": name, "action": "enrich"}], group_id=group["id"], discovery_tag=False, confirm_business_changes=True)
    assert len(next(g for g in operator.get("/api/target-groups").json() if g["id"] == group["id"])["target_ids"]) == 1


def test_500_targets_in_one_import_then_the_targets_of_that_import(operator):
    job = discover(operator, "bulk.test", methods=["axfr"])
    names = [host(i) for i in range(21, 521)]
    forget(operator, names)
    r = apply(operator, job, add(names))
    assert r.status_code == 200, r.text
    assert r.json()["summary"]["create"] == 500 and r.json()["summary"]["skipped"] == 0
    mine = operator.get("/api/targets", params={"discovery": job["id"]}).json()
    assert {t["value"] for t in mine} == set(names)
    assert all(t["dns"]["created"] and TAG in t["tags"] and t["dns"]["domains"] == ["bulk.test"] for t in mine)
    assert apply(operator, job, add(names + [host(1)])).status_code == 422          # the volume limit is unchanged


def test_provenance_filters_and_manual_targets_are_untouched(operator, job):
    manual = f"manual-{uuid.uuid4().hex[:6]}.example.org"
    t = operator.post("/api/targets", json={"value": manual})
    assert t.status_code == 201
    created = t.json()
    assert created["tags"] == []                                                # no tag, group or provenance forced on a manual target
    listed = next(x for x in operator.get("/api/targets", params={"q": manual}).json() if x["value"] == manual)
    assert listed["dns"] is None
    assert manual not in {x["value"] for x in operator.get("/api/targets", params={"provenance": "dns"}).json()}
    name = host(261)
    forget(operator, [name])
    apply(operator, job, add([name]))
    seen = {x["value"]: x for x in operator.get("/api/targets", params={"provenance": "dns"}).json()}
    assert name in seen and seen[name]["dns"]["methods"] == ["axfr"] and seen[name]["dns"]["first_seen"]
    detail = operator.get(f"/api/targets/{seen[name]['id']}/dns").json()
    assert detail["provenance"]["created"] is True and detail["provenance"]["discovery_id"] == job["id"]
    assert operator.get("/api/targets", params={"discovery": str(uuid.uuid4())}).json() == []


def test_two_domains_have_their_own_group_and_targets(operator, job):
    names = [host(271), host(272)]
    forget(operator, names + ["srv01.client.test"])
    client = discover(operator, "client.test", methods=["dns", "axfr"])
    assert results(operator, client)["default_group"]["name"] == "DNS — client.test"
    apply(operator, job, add(names), group_name="DNS — bulk.test", reuse_group=True)
    apply(operator, client, add(["srv01.client.test"]), group_name="DNS — client.test", reuse_group=True)
    by = {g["name"]: set(g["target_ids"]) for g in operator.get("/api/target-groups").json()}
    assert targets_of(operator, "srv01.client.test")[0]["id"] in by["DNS — client.test"]
    assert targets_of(operator, "srv01.client.test")[0]["id"] not in by["DNS — bulk.test"]
    assert {t["value"] for t in operator.get("/api/targets", params={"discovery": client["id"]}).json()} >= {"srv01.client.test"}
    assert not {t["value"] for t in operator.get("/api/targets", params={"discovery": job["id"]}).json()} & {"srv01.client.test"}


def test_an_import_never_launches_a_scan_nor_touches_a_definition(operator, admin, job):
    def snapshot():
        runs = admin.get("/api/scan-runs").json()
        return (len(runs) if isinstance(runs, list) else len(runs["items"])), [(d["id"], d["name"]) for d in operator.get("/api/scan-definitions").json()]
    before = snapshot()
    name = host(281)
    forget(operator, [name])
    assert apply(operator, job, add([name]), group_name=f"ux-{uuid.uuid4().hex[:6]}").status_code == 200
    assert snapshot() == before


def test_roles_and_conflicts(operator, user, auditor, job):
    name = host(291)
    forget(operator, [name])
    assert apply(user, job, add([name])).status_code in (403, 404)               # an ordinary user cannot import
    assert not targets_of(operator, name)
    assert apply(operator, job, add([name]), group_id=str(uuid.uuid4())).status_code == 404
    assert apply(operator, job, add([name]), on_conflict="abort").status_code == 200
    # the list with provenance is readable by a read-only account
    assert auditor.get("/api/targets", params={"provenance": "dns"}).status_code == 200
