import uuid

from conftest import POLICY, PROFILE, make_definition, wait_final


def test_ipsec_profiles_policies_and_definitions_are_separate_from_tls(operator, user, catalog):
    policy_content = {"allowed_versions": ["IKEv1", "IKEv2"], "allowed_encryption": ["AES_GCM_16", "AES_CBC"],
                      "allowed_integrity": ["SHA256", "NONE"], "allowed_prf": ["PRF_HMAC_SHA2_256"], "allowed_dh_groups": ["14", "ECP_256"]}
    profile_content = {"ike": {"versions": ["IKEv1", "IKEv2"], "ports": [500, 4500], "timeout_ms": 300,
                                "retries": 0, "nat_t": True, "aggressive_mode": False}}
    policy = operator.post("/api/policies", json={"name": f"ipsec-{uuid.uuid4().hex[:6]}", "technology": "ipsec", "content": policy_content})
    assert policy.status_code == 201, policy.text
    profile = operator.post("/api/profiles", json={"name": f"ipsec-{uuid.uuid4().hex[:6]}", "technology": "ipsec", "content": profile_content})
    assert profile.status_code == 201, profile.text
    assert operator.post(f"/api/policies/{policy.json()['id']}/publish").status_code == 200
    assert operator.post(f"/api/profiles/{profile.json()['id']}/publish").status_code == 200
    assert all(x["technology"] == "tls" for x in operator.get("/api/profiles").json())
    assert [x["id"] for x in operator.get("/api/profiles", params={"technology": "ipsec"}).json()] == [profile.json()["id"]]

    target = user.post("/api/targets", json={"value": "lab-tls", "ports": "443"})
    assert target.status_code in (201, 409), target.text
    target_id = target.json()["id"] if target.status_code == 201 else next(t["id"] for t in user.get("/api/targets", params={"q": "lab-tls"}).json() if t["ports"] == "443")
    body = {"name": f"IKE integration {uuid.uuid4().hex[:5]}", "control_type": "ipsec", "target_ids": [target_id],
            "profile_id": profile.json()["id"], "policy_ids": [policy.json()["id"]]}
    definition = user.post("/api/scan-definitions", json=body)
    assert definition.status_code == 201, definition.text
    assert definition.json()["control_type"] == "ipsec"
    assert user.post("/api/scan-definitions", json={**body, "name": "cross-family", "profile_id": catalog["profile"]}).status_code == 422
    assert user.post("/api/scan-definitions", json={**body, "name": "cross-policy", "policy_ids": [catalog["policy"]]}).status_code == 422

    launched = user.post(f"/api/scan-definitions/{definition.json()['id']}/run")
    assert launched.status_code == 202, launched.text
    result = wait_final(user, launched.json()["run_id"], timeout=45)
    assert result["status"] in ("completed", "partial"), result
    assert result["control_type"] == "ipsec"
    assert result["endpoints"] == []
    assert result["ipsec_observations"]
    assert all(row["status"] in {"timeout", "observed", "indeterminate", "error"} for row in result["ipsec_observations"])
    assert all(report["format"] in {"html", "md", "csv"} for report in result["reports"])


def test_generic_profile_runs_tls_and_ipsec_together_without_mixing_policies(operator, user, catalog):
    ike_policy_content = {"allowed_versions": ["IKEv1", "IKEv2"], "allowed_encryption": ["AES_GCM_16"],
                          "allowed_integrity": ["SHA256"], "allowed_prf": ["PRF_HMAC_SHA2_256"], "allowed_dh_groups": ["14"]}
    ike_policy = operator.post("/api/policies", json={"name": f"multi-ike-{uuid.uuid4().hex[:6]}",
                                                       "technology": "ipsec", "content": ike_policy_content}).json()
    assert operator.post(f"/api/policies/{ike_policy['id']}/publish").status_code == 200
    generic_profile = operator.post("/api/profiles", json={
        "name": f"generic-{uuid.uuid4().hex[:6]}", "technology": "generic",
        "content": {"tls": PROFILE, "ipsec": {"ike": {"versions": ["IKEv2"], "ports": [500],
                                                           "timeout_ms": 250, "retries": 0, "nat_t": True,
                                                           "aggressive_mode": False}}},
    })
    assert generic_profile.status_code == 201, generic_profile.text
    assert operator.post(f"/api/profiles/{generic_profile.json()['id']}/publish").status_code == 200
    assert any(item["id"] == generic_profile.json()["id"] for item in operator.get("/api/profiles", params={"technology": "generic"}).json())

    target = user.post("/api/targets", json={"value": "lab-tls", "ports": "443"})
    assert target.status_code in (201, 409), target.text
    target_id = target.json()["id"] if target.status_code == 201 else next(
        item["id"] for item in user.get("/api/targets", params={"q": "lab-tls"}).json() if item["ports"] == "443")
    definition = user.post("/api/scan-definitions", json={
        "name": f"generic-run-{uuid.uuid4().hex[:5]}", "enabled_controls": ["tls", "ipsec"],
        "target_ids": [target_id], "profile_id": generic_profile.json()["id"],
        "policy_ids": [catalog["policy"], ike_policy["id"]],
    })
    assert definition.status_code == 201, definition.text
    launched = user.post(f"/api/scan-definitions/{definition.json()['id']}/run")
    assert launched.status_code == 202, launched.text
    result = wait_final(user, launched.json()["run_id"], timeout=60)
    assert result["status"] in ("completed", "partial"), result
    assert result["control_type"] == "multi"
    assert result["endpoints"]
    assert result["ipsec_observations"]
    formats = {report["format"] for report in result["reports"]}
    assert {"html", "ipsec_html"} <= formats
