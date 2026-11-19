from types import SimpleNamespace

from orion_app.services.ipsec import evaluate_policy, parse_ike_scan, probe, validate_ipsec_policy, validate_ipsec_profile


POLICY = {"allowed_versions": ["IKEv2"], "allowed_encryption": ["AES_GCM_16"], "allowed_integrity": ["NONE"],
          "allowed_prf": ["PRF_HMAC_SHA2_256"], "allowed_dh_groups": ["ECP_256"]}


def test_profile_validation_requires_safe_udp_ike_configuration():
    validate_ipsec_profile({"ike": {"versions": ["IKEv1", "IKEv2"], "ports": [500, 4500], "timeout_ms": 1000,
                                      "retries": 1, "aggressive_mode": False, "ikev1_transforms": ["7/256,4,1,14"]}})
    try:
        validate_ipsec_profile({"ike": {"versions": ["IKEv1"], "ports": [500], "aggressive_mode": True}})
    except ValueError as error:
        assert "aggressive" in str(error)
    else:
        raise AssertionError("Aggressive Mode must be disabled")


def test_ipsec_policy_schema_is_separate_and_explicit():
    validate_ipsec_policy(POLICY)
    try:
        validate_ipsec_policy({"allowed_versions": ["TLSv1.3"]})
    except ValueError:
        pass
    else:
        raise AssertionError("TLS policy cannot be accepted as IPsec policy")


def test_ikev1_and_ikev2_observed_proposals_are_parsed_without_exhaustive_claims():
    for version, port, line in (
        ("IKEv1", 500, "10.0.0.1: Main Mode HDR=(version=1.0) SA=(encryption=AES_CBC hash=SHA256 auth=PSK group=14)"),
        ("IKEv2", 4500, "10.0.0.1: IKE_SA_INIT HDR=(version=2.0) SA=(encryption=AES_GCM_16, key length=256, prf=PRF_HMAC_SHA2_256, integrity=NONE, group=ECP_256)"),
    ):
        obs = parse_ike_scan(line, version, port)
        assert obs["status"] == "observed" and obs["ike_version"] == version
        assert obs["evidence"]["proposal_scope"] == "one response; not an exhaustive list"
        assert obs["proposal"]["encryption"]
        if version == "IKEv2":
            assert obs["proposal"]["prf"] == "PRF_HMAC_SHA2_256" and obs["proposal"]["key_length_bits"] == "256"


def test_empty_malformed_and_silent_responses_do_not_become_compliant():
    assert parse_ike_scan("", "IKEv2", 500)["status"] == "timeout"
    assert parse_ike_scan("random UDP payload", "IKEv2", 500)["status"] == "timeout"
    obs = parse_ike_scan("HDR=(version=2.0) SA=(broken)", "IKEv2", 500)
    obs["ike_version"] = "IKEv2"
    assert evaluate_policy(obs, POLICY) == "indeterminate"


def test_policy_requires_every_crypto_dimension_and_detects_observed_mismatch():
    complete = {"status": "observed", "ike_version": "IKEv2", "proposal": {
        "encryption": "AES_GCM_16", "integrity": "NONE", "prf": "PRF_HMAC_SHA2_256", "dh_group": "ECP_256"}}
    assert evaluate_policy(complete, POLICY) == "compliant"
    aliases = {"allowed_versions": ["IKEv2"], "allowed_encryption": ["AES-GCM"], "allowed_integrity": ["SHA-256"],
               "allowed_prf": ["PRF-HMAC-SHA2-256"], "allowed_dh_groups": ["MODP-2048"]}
    alias_observation = {**complete, "proposal": {"encryption": "AES_GCM_16", "integrity": "HMAC_SHA2_256_128",
                                                   "prf": "HMAC_SHA2_256", "dh_group": "14:modp2048"}}
    assert evaluate_policy(alias_observation, aliases) == "compliant"
    assert evaluate_policy({**complete, "proposal": {**complete["proposal"], "encryption": "3DES"}}, POLICY) == "non_compliant"
    assert evaluate_policy({**complete, "proposal": {"encryption": "AES_GCM_16"}}, POLICY) == "indeterminate"
    assert evaluate_policy({"status": "indeterminate", "ike_version": "", "proposal": {}}, POLICY) == "indeterminate"


def test_probe_uses_bounded_ikev2_and_nat_t_arguments_and_handles_timeout(monkeypatch):
    monkeypatch.setattr("orion_app.services.ipsec.shutil.which", lambda _: "/usr/bin/ike-scan")
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        return SimpleNamespace(returncode=0, stdout="HDR=(version=2.0) SA=(encryption=AES_GCM hash=NONE auth=NONE group=ECP_256)", stderr="")

    monkeypatch.setattr("orion_app.services.ipsec.subprocess.run", fake_run)
    assert probe("192.0.2.1", "IKEv2", 4500, 500, 0)["status"] == "observed"
    assert "--ikev2" in captured["args"] and "--nat-t" in captured["args"]
    assert "--retry=1" in captured["args"] and "--timeout=500" in captured["args"]

    def timeout(*args, **kwargs):
        from subprocess import TimeoutExpired
        raise TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr("orion_app.services.ipsec.subprocess.run", timeout)
    assert probe("192.0.2.1", "IKEv1", 500, 500, 0)["status"] == "timeout"

    monkeypatch.setattr("orion_app.services.ipsec.subprocess.run", fake_run)
    probe("192.0.2.1", "IKEv1", 4500, 500, 0, False, ["7/256,4,1,14"])
    assert "--dport=4500" in captured["args"] and "--nat-t" not in captured["args"]
    assert "--trans=7/256,4,1,14" in captured["args"] and "--ikev2" not in captured["args"]
