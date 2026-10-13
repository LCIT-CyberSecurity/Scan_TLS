"""The progress panel of a running scan: a synthetic plan derived from the snapshot, only while the scan is active."""
from __future__ import annotations

import copy
import uuid

from conftest import LAB, PROFILE, make_definition, wait_final, wait_for


def test_active_run_exposes_a_plan_and_a_finished_one_does_not(user, operator, catalog):
    content = copy.deepcopy(PROFILE)
    content["checks"]["certificate"]["revocation"] = {"enabled": True, "ocsp": False, "crl": True}
    content["checks"]["tls"] = {"hostname_san": {"enabled": True}, "tls_compression": True, "timeout_seconds": 5}
    profile = operator.post("/api/profiles", json={"name": f"plan-{uuid.uuid4().hex[:6]}", "content": content}).json()
    assert operator.post(f"/api/profiles/{profile['id']}/publish").status_code == 200
    definition = make_definition(user, {**catalog, "profile": profile["id"]}, [LAB], name=f"plan-{uuid.uuid4().hex[:6]}")
    run_id = user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"]
    seen = wait_for(lambda: (r := user.get(f"/api/scan-runs/{run_id}").json())["status"] in ("queued", "running") and r.get("plan") and r, timeout=60)
    plan = seen["plan"]
    assert plan["targets"] == 1 and plan["ports"] == ["443,8443"] and plan["crypto"] == "standard"
    assert plan["certificate"] and plan["trust"] and plan["public_store"] and plan["private_stores"] == [] and plan["revocation"] is True
    assert plan["tls_checks"] == 2 and plan["policies"] and plan["formats"]      # timeout_seconds is a setting, not a check
    final = wait_final(user, run_id)
    assert final["status"] in ("completed", "partial") and final["plan"] is None
    assert "config_snapshot" not in user.get(f"/api/scan-runs/{run_id}").json()   # the plan is not a way to read the snapshot
