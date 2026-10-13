"""Administered trust stores end to end: admin API, profile selection, immutable snapshots, and real scans of a private PKI (lab-tls)."""
from __future__ import annotations

import base64
import copy
import threading
import uuid

import httpx
import pytest

from conftest import LAB, PROFILE, make_definition, wait_final

PKI_HOST = "intranet.acme.local"  # network alias of lab-tls: the private-PKI scenarios are scanned under their real name
PORTS = {"full": "8470", "incomplete": "8471", "wrong_san": "8472", "expired": "8473", "revoked": "8474", "globex": "8475"}


def lab_file(name: str) -> bytes:
    r = httpx.get(f"http://{LAB}/pki/{name}", timeout=15)
    assert r.status_code == 200, name
    return r.content


def files(*names: str) -> list[dict]:
    return [{"filename": n, "content_b64": base64.b64encode(lab_file(n)).decode()} for n in names]


def uniq(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}"


def create_store(admin, name: str, *names: str) -> dict:
    r = admin.post("/api/admin/trust-stores", json={"name": name, "description": "test", "files": files(*names)})
    assert r.status_code == 201, r.text
    return r.json()


def profile_with(operator, store_ids: list[str] | None, *, revocation: bool = False, public: bool = True) -> str:
    content = copy.deepcopy(PROFILE)
    content["scan"]["ports"] = ",".join(PORTS.values())
    trust = {"enabled": True, "public_store": {"enabled": public}}
    if store_ids is not None:
        trust["private_stores"] = store_ids
    content["checks"] = {"certificate": {"enabled": True, "expires_within_days": 30, "trust": trust,
                                         "revocation": {"enabled": revocation, "ocsp": False, "crl": True, "allow_private_urls": True}},
                         "tls": {"hostname_san": True}}
    r = operator.post("/api/profiles", json={"name": uniq("pki"), "content": content})
    assert r.status_code == 201, r.text
    assert operator.post(f"/api/profiles/{r.json()['id']}/publish").status_code == 200
    return r.json()["id"]


def scan(user, operator, catalog, profile_id: str) -> dict:
    definition = make_definition(user, {**catalog, "profile": profile_id}, [PKI_HOST], name=uniq("pkiscan"))
    r = user.post(f"/api/scan-definitions/{definition['id']}/run")
    assert r.status_code in (200, 201, 202), r.text
    return wait_final(user, r.json()["run_id"])


def endpoints(run: dict) -> dict[str, dict]:
    return {e["port"]: e for e in run["endpoints"]}


# ---------------------------------------------------------------------------------------------
# permissions and the built-in store
# ---------------------------------------------------------------------------------------------
def test_only_administrators_manage_stores(admin, operator, user, auditor):
    store = create_store(admin, uniq("perm"), "ACME-Root-CA.crt")
    body = {"name": uniq("x"), "files": files("ACME-Root-CA.crt")}
    for api in (operator, user, auditor):
        assert api.get("/api/admin/trust-stores").status_code == 403
        assert api.post("/api/admin/trust-stores", json=body).status_code == 403
        assert api.post("/api/admin/trust-stores/inspect", json={"files": body["files"]}).status_code == 403
        assert api.post(f"/api/admin/trust-stores/{store['id']}/versions", json={"files": body["files"]}).status_code == 403
        assert api.put(f"/api/admin/trust-stores/{store['id']}", json={"active": False}).status_code == 403
        assert api.delete(f"/api/admin/trust-stores/{store['id']}").status_code == 403
        assert api.get(f"/api/admin/trust-stores/{store['id']}").status_code == 403
    anonymous = httpx.Client(base_url=str(admin.http.base_url))
    assert anonymous.get("/api/admin/trust-stores").status_code == 401
    assert anonymous.post("/api/admin/trust-stores", json=body).status_code in (401, 403)


def test_csrf_is_required(admin):
    stripped = httpx.Client(base_url=str(admin.http.base_url), cookies=admin.http.cookies)
    r = stripped.post("/api/admin/trust-stores", json={"name": uniq("csrf"), "files": files("ACME-Root-CA.crt")})
    assert r.status_code == 403


def test_builtin_public_store_is_listed_and_read_only(admin, operator, user):
    listing = admin.get("/api/admin/trust-stores").json()
    public = next(s for s in listing if s["builtin"])
    assert public["id"] == "public-web-pki" and public["type"] == "public" and public["certificate_count"] > 100 and public["active"] is True
    assert admin.put("/api/admin/trust-stores/public-web-pki", json={"active": False}).status_code == 422  # not a managed store: nothing can edit it
    assert admin.delete("/api/admin/trust-stores/public-web-pki").status_code == 422
    assert admin.post("/api/admin/trust-stores/public-web-pki/versions", json={"files": files("ACME-Root-CA.crt")}).status_code == 422
    selectable = user.get("/api/trust-stores").json()  # what a profile can select: no certificate content at all
    assert selectable[0]["builtin"] is True and all("pem" not in s and "certificates" not in s for s in selectable)
    assert operator.get("/api/trust-stores").status_code == 200


# ---------------------------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------------------------
def test_inspect_shows_what_would_be_imported(admin):
    r = admin.post("/api/admin/trust-stores/inspect", json={"files": files("ACME-Root-CA.crt", "ACME-Issuing-CA.crt")})
    assert r.status_code == 200 and r.json()["valid"] is True
    certs = [c for f in r.json()["files"] for c in f["certificates"]]
    assert {c["role"] for c in certs} == {"anchor", "intermediate"}
    root = next(c for c in certs if c["role"] == "anchor")
    assert root["subject"].startswith("CN=ACME-Root-CA") and root["key_type"] == "RSA" and root["key_size"] == 2048 and len(root["fingerprint_sha256"]) == 64
    assert root["basic_constraints"]["ca"] is True and "key_cert_sign" in root["key_usage"]


def test_private_keys_and_pkcs12_are_refused(admin):
    for name in ("private-key-sample.pem", "bundle.p12"):
        inspected = admin.post("/api/admin/trust-stores/inspect", json={"files": files(name)}).json()
        assert inspected["valid"] is False and inspected["files"][0]["error"]
        r = admin.post("/api/admin/trust-stores", json={"name": uniq("bad"), "files": files(name)})
        assert r.status_code == 422, name
    assert "private key" in admin.post("/api/admin/trust-stores", json={"name": uniq("bad"), "files": files("private-key-sample.pem")}).json()["detail"].lower()
    mixed = files("ACME-Root-CA.crt") + files("private-key-sample.pem")
    assert admin.post("/api/admin/trust-stores", json={"name": uniq("bad"), "files": mixed}).status_code == 422
    assert all(s["name"] != "bad" for s in admin.get("/api/admin/trust-stores").json())  # nothing half-created


def test_invalid_requests(admin):
    ok = files("ACME-Root-CA.crt")
    assert admin.post("/api/admin/trust-stores", json={"name": "", "files": ok}).status_code == 422
    assert admin.post("/api/admin/trust-stores", json={"name": "a,b", "files": ok}).status_code == 422
    assert admin.post("/api/admin/trust-stores", json={"name": "TLS Scan Public Web PKI", "files": ok}).status_code == 422
    assert admin.post("/api/admin/trust-stores", json={"name": uniq("n"), "files": []}).status_code == 422
    assert admin.post("/api/admin/trust-stores", json={"name": uniq("n"), "files": [{"filename": "x", "content_b64": "%%%"}]}).status_code == 422
    big = [{"filename": "big.pem", "content_b64": base64.b64encode(b"A" * 600_000).decode()}]
    assert admin.post("/api/admin/trust-stores", json={"name": uniq("n"), "files": big}).status_code == 422
    assert admin.post("/api/admin/trust-stores", json={"name": uniq("n"), "files": files("ACME-Issuing-CA.crt")}).status_code == 422  # no Root CA: trusts nothing
    assert admin.get(f"/api/admin/trust-stores/{uuid.uuid4()}").status_code == 404


def test_create_list_detail_and_duplicate_name(admin):
    name = uniq("acme")
    store = create_store(admin, name, "ACME-Root-CA.crt", "ACME-Issuing-CA.crt")
    assert store["version"] == 1 and store["certificate_count"] == 2 and store["anchor_count"] == 1 and store["active"] is True and store["builtin"] is False
    roles = {c["subject"].split(",")[0]: c["role"] for c in store["certificates"]}
    assert roles == {"CN=ACME-Root-CA": "anchor", "CN=ACME-Issuing-CA": "intermediate"}
    assert all("pem" not in c for c in store["certificates"])  # no raw certificate in the API
    assert admin.post("/api/admin/trust-stores", json={"name": name, "files": files("Globex-Root-CA.crt")}).status_code == 409
    listing = admin.get("/api/admin/trust-stores").json()
    assert any(s["id"] == store["id"] and s["certificate_count"] == 2 for s in listing)
    assert len(admin.get(f"/api/admin/trust-stores/{store['id']}").json()["versions"]) == 1


def test_duplicate_certificates_are_merged(admin):
    both = files("ACME-Root-CA.crt", "ACME-Root-CA.crt")
    store = admin.post("/api/admin/trust-stores", json={"name": uniq("dup"), "files": both}).json()
    assert store["certificate_count"] == 1


# ---------------------------------------------------------------------------------------------
# versions
# ---------------------------------------------------------------------------------------------
def test_versions_are_immutable_and_remain_consultable(admin):
    store = create_store(admin, uniq("ver"), "ACME-Root-CA.crt")
    v1_hash = store["content_sha256"]
    r = admin.post(f"/api/admin/trust-stores/{store['id']}/versions", json={"files": files("ACME-Issuing-CA.crt"), "comment": "add the issuing CA"})
    assert r.status_code == 201 and r.json()["version"] == 2 and r.json()["certificate_count"] == 2 and r.json()["content_sha256"] != v1_hash
    r = admin.post(f"/api/admin/trust-stores/{store['id']}/versions", json={"files": files("Globex-Root-CA.crt"), "base": "empty", "comment": "replace"})
    assert r.json()["version"] == 3 and r.json()["certificate_count"] == 1
    v1 = admin.get(f"/api/admin/trust-stores/{store['id']}/versions/1").json()
    assert v1["content_sha256"] == v1_hash and [c["subject"].split(",")[0] for c in v1["certificates"]] == ["CN=ACME-Root-CA"]
    v2 = admin.get(f"/api/admin/trust-stores/{store['id']}/versions/2").json()
    assert v2["anchor_count"] == 1 and v2["intermediate_count"] == 1 and v2["comment"] == "add the issuing CA"
    assert [v["version"] for v in admin.get(f"/api/admin/trust-stores/{store['id']}").json()["versions"]] == [3, 2, 1]
    assert admin.get(f"/api/admin/trust-stores/{store['id']}/versions/9").status_code == 404


def test_remove_certificates_and_guard_rails(admin):
    store = create_store(admin, uniq("rm"), "ACME-Root-CA.crt", "ACME-Issuing-CA.crt")
    inter = next(c for c in store["certificates"] if c["role"] == "intermediate")
    r = admin.post(f"/api/admin/trust-stores/{store['id']}/versions", json={"remove": [inter["fingerprint_sha256"]]})
    assert r.status_code == 201 and r.json()["certificate_count"] == 1
    root = next(c for c in r.json()["certificates"])
    assert admin.post(f"/api/admin/trust-stores/{store['id']}/versions", json={"remove": [root["fingerprint_sha256"]]}).status_code == 422  # would leave no Root CA
    assert admin.post(f"/api/admin/trust-stores/{store['id']}/versions", json={}).status_code == 422  # nothing to change
    assert admin.post(f"/api/admin/trust-stores/{store['id']}/versions", json={"files": files("private-key-sample.pem")}).status_code == 422
    assert admin.get(f"/api/admin/trust-stores/{store['id']}").json()["version"] == 2  # failed attempts created nothing


def test_concurrent_publications_never_collide(admin):
    store = create_store(admin, uniq("race"), "ACME-Root-CA.crt")
    results = []

    def publish(n: int) -> None:
        r = admin.http.post(f"/api/admin/trust-stores/{store['id']}/versions", json={"files": files("ACME-Issuing-CA.crt" if n % 2 else "Globex-Root-CA.crt"), "comment": str(n)})
        results.append(r.status_code)

    threads = [threading.Thread(target=publish, args=(n,)) for n in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert set(results) <= {201} , results
    versions = [v["version"] for v in admin.get(f"/api/admin/trust-stores/{store['id']}").json()["versions"]]
    assert sorted(versions) == list(range(1, 8))  # strictly sequential, none lost, none duplicated


# ---------------------------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------------------------
def test_profile_selection_is_validated_and_audited(admin, operator):
    store = create_store(admin, uniq("sel"), "ACME-Root-CA.crt")
    content = copy.deepcopy(PROFILE)
    trust = content["checks"]["certificate"]["trust"]

    def post(private_stores):
        trust["private_stores"] = private_stores
        return operator.post("/api/profiles", json={"name": uniq("p"), "content": copy.deepcopy(content)})

    assert post([str(uuid.uuid4())]).status_code == 422          # unknown
    assert post(["not-a-uuid"]).status_code == 422
    assert post([store["id"], store["id"]]).status_code == 422   # duplicates
    assert post("acme").status_code == 422                       # a name is not an identifier, and not a list
    assert post(["Client A"]).status_code == 422                  # referencing by name is refused
    trust["enabled"] = False
    assert post([store["id"]]).status_code == 422                # the chain verification is off
    trust["enabled"] = True
    created = post([store["id"]])
    assert created.status_code == 201, created.text
    usage = admin.get(f"/api/admin/trust-stores/{store['id']}").json()["profiles"]
    assert [p["name"] for p in usage] == [created.json()["name"]]
    events = admin.get("/api/admin/audit", params={"action": "profiles.trust_stores_change"}).json()
    assert any(e["detail"]["profile"] == created.json()["name"] and e["detail"]["added"] == [store["name"]] for e in events)
    # inactive stores can no longer be selected
    assert admin.put(f"/api/admin/trust-stores/{store['id']}", json={"active": False}).status_code == 200
    assert post([store["id"]]).status_code == 422


def test_raw_certificates_and_paths_cannot_be_smuggled_into_a_profile(operator):
    for trust in ({"custom_stores": [{"name": "x", "type": "file", "path": "/etc/passwd"}]},
                  {"inline_stores": [{"name": "x", "store_id": "m", "anchors": ["-----BEGIN CERTIFICATE-----"]}]}):
        content = copy.deepcopy(PROFILE)
        content["checks"]["certificate"]["trust"].update(trust)
        assert operator.post("/api/profiles", json={"name": uniq("smug"), "content": content}).status_code == 422


def test_existing_profiles_are_untouched(operator, catalog):
    profile = next(p for p in operator.get("/api/profiles").json() if p["id"] == catalog["profile"])
    assert "private_stores" not in profile["versions"][0]["content"]["checks"]["certificate"]["trust"]


# ---------------------------------------------------------------------------------------------
# lifecycle: deactivation and deletion
# ---------------------------------------------------------------------------------------------
def test_referenced_stores_cannot_be_deleted_but_can_be_deactivated(admin, operator, user, catalog):
    unused = create_store(admin, uniq("unused"), "Globex-Root-CA.crt")
    assert admin.delete(f"/api/admin/trust-stores/{unused['id']}").status_code == 204
    assert admin.get(f"/api/admin/trust-stores/{unused['id']}").status_code == 404

    store = create_store(admin, uniq("kept"), "ACME-Root-CA.crt")
    profile_id = profile_with(operator, [store["id"]])
    assert admin.delete(f"/api/admin/trust-stores/{store['id']}").status_code == 409  # referenced by a profile
    # a deactivated store blocks the launch explicitly: it never silently downgrades the verification
    assert admin.put(f"/api/admin/trust-stores/{store['id']}", json={"active": False}).json()["active"] is False
    definition = make_definition(user, {**catalog, "profile": profile_id}, [PKI_HOST], name=uniq("blocked"))
    r = user.post(f"/api/scan-definitions/{definition['id']}/run")
    assert r.status_code in (409, 422) and "disabled" in r.text
    assert admin.put(f"/api/admin/trust-stores/{store['id']}", json={"active": True}).json()["active"] is True
    assert user.post(f"/api/scan-definitions/{definition['id']}/run").status_code in (200, 201, 202)
    ids = {e["action"] for e in admin.get("/api/admin/audit", params={"action": "trust_store."}).json() if e["resource_id"] == store["id"]}
    assert {"trust_store.create", "trust_store.version_publish", "trust_store.deactivate", "trust_store.activate"} <= ids
    deleted_run = admin.delete(f"/api/admin/trust-stores/{store['id']}")
    assert deleted_run.status_code == 409  # now referenced by a scan too


# ---------------------------------------------------------------------------------------------
# real scans of a private PKI (scenarios A to G)
# ---------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def acme(admin):
    return create_store(admin, uniq("ACME PKI"), "ACME-Root-CA.crt")


@pytest.fixture(scope="module")
def globex(admin):
    return create_store(admin, uniq("Globex PKI"), "Globex-Root-CA.crt", "Globex-Issuing-CA.crt")


@pytest.fixture(scope="module")
def run_public(user, operator, catalog):
    return scan(user, operator, catalog, profile_with(operator, None, revocation=True))


@pytest.fixture(scope="module")
def run_acme(user, operator, catalog, acme):
    return scan(user, operator, catalog, profile_with(operator, [acme["id"]], revocation=True))


@pytest.fixture(scope="module")
def run_globex(user, operator, catalog, globex):
    return scan(user, operator, catalog, profile_with(operator, [globex["id"]]))


def test_A_without_the_private_authority_nothing_is_trusted(run_public):
    assert run_public["status"] in ("completed", "partial"), run_public
    eps = endpoints(run_public)
    assert set(PORTS.values()) <= set(eps)
    for port in PORTS.values():
        assert eps[port]["certificate"]["trust_classification"] == "UNTRUSTED"
        assert eps[port]["certificate"]["trusted_by"] in (None, [], ())
    assert run_public["trust_stores"] == []


def test_B_selected_root_gives_private_trusted_with_provenance(run_acme, acme):
    eps = endpoints(run_acme)
    full = eps[PORTS["full"]]["certificate"]
    assert full["trust_classification"] == "PRIVATE_TRUSTED" and full["chain_validation_status"] == "Passed"
    assert full["trusted_by"] == [f"{acme['name']} (v1)"] and "ACME-Root-CA" in full["trust_anchor"]
    results = {r["store_name"]: r for r in full["trust_store_results"]}
    assert results[f"{acme['name']} (v1)"]["status"] == "trusted" and "TLS Scan Public Web PKI" in results and results["TLS Scan Public Web PKI"]["status"] == "untrusted"
    # provenance of the run: exact store, version, content hash and anchors (no raw certificate)
    ref = run_acme["trust_stores"][0]
    assert ref["id"] == acme["id"] and ref["version"] == 1 and ref["content_sha256"] == acme["content_sha256"]
    assert ref["anchors"] and "ACME-Root-CA" in ref["anchors"][0] and "pem" not in ref


def test_B_chain_trust_is_not_a_global_verdict(run_acme):
    eps = endpoints(run_acme)
    wrong = eps[PORTS["wrong_san"]]
    assert wrong["certificate"]["trust_classification"] == "PRIVATE_TRUSTED"  # D: the chain is fine...
    check = {c["check_id"]: c for c in wrong["tls_checks"]}["hostname_san"]
    assert check["status"] == "FAIL"                                          # ...and the name still is not
    assert {c["check_id"]: c for c in eps[PORTS["full"]]["tls_checks"]}["hostname_san"]["status"] == "PASS"
    globex_port = eps[PORTS["globex"]]
    assert {c["check_id"]: c for c in globex_port["tls_checks"]}["hostname_san"]["status"] == "FAIL"


def test_C_expired_certificate_is_not_masked(run_acme, run_public):
    cert = endpoints(run_acme)[PORTS["expired"]]["certificate"]
    assert cert["trust_classification"] == "UNTRUSTED"
    reasons = " ".join(r.get("validation_error", "") for r in cert["trust_store_results"]).lower()
    assert "expired" in reasons
    assert cert["remaining_days"] is None or cert["remaining_days"] < 0
    assert str(cert["status"]).lower() != "valid"


def test_E_revoked_certificate_is_never_presented_as_good(run_acme):
    eps = endpoints(run_acme)
    assert eps[PORTS["revoked"]]["certificate"]["revocation_status"] == "Revoked"
    assert eps[PORTS["revoked"]]["certificate"]["trust_classification"] == "PRIVATE_TRUSTED"  # the chain is trusted, the certificate is revoked
    assert eps[PORTS["revoked"]]["compliance_status"] == "non_compliant"
    assert eps[PORTS["full"]]["certificate"]["revocation_status"] != "Revoked"


def test_F_incomplete_chain_is_not_trusted(run_acme):
    cert = endpoints(run_acme)[PORTS["incomplete"]]["certificate"]
    assert cert["trust_classification"] == "UNTRUSTED"  # the store holds the Root CA only: the issuing CA is not proven


def test_F_the_administrator_can_supply_the_intermediate(admin, operator, user, catalog):
    store = create_store(admin, uniq("ACME full"), "ACME-Root-CA.crt", "ACME-Issuing-CA.crt")
    run = scan(user, operator, catalog, profile_with(operator, [store["id"]]))
    cert = endpoints(run)[PORTS["incomplete"]]["certificate"]
    assert cert["trust_classification"] == "PRIVATE_TRUSTED" and "ACME-Root-CA" in cert["trust_anchor"]  # the anchor is still the Root CA


def test_G_another_customers_root_is_not_trusted(run_acme, run_globex):
    assert endpoints(run_acme)[PORTS["globex"]]["certificate"]["trust_classification"] == "UNTRUSTED"
    eps = endpoints(run_globex)
    assert eps[PORTS["globex"]]["certificate"]["trust_classification"] == "PRIVATE_TRUSTED"
    for port in (PORTS["full"], PORTS["incomplete"], PORTS["wrong_san"], PORTS["expired"], PORTS["revoked"]):
        assert eps[port]["certificate"]["trust_classification"] == "UNTRUSTED"


def test_findings_follow_the_trust_result(run_public, run_acme):
    def has_untrusted(run, port):
        eid = endpoints(run)[port]["endpoint_id"]
        return any(f["finding_id"] == "CERTIFICATE_CHAIN_UNTRUSTED" and eid in f["affected_endpoint_ids"] for f in run["findings"])

    assert has_untrusted(run_public, PORTS["full"]) and not has_untrusted(run_acme, PORTS["full"])
    assert has_untrusted(run_acme, PORTS["globex"])


def test_snapshots_pin_the_exact_version(admin, operator, user, catalog, acme, run_acme):
    before = admin.get(f"/api/scan-runs/{run_acme['id']}").json()
    ref = before["trust_stores"][0]
    assert before["config_snapshot"]["checks"]["certificate"]["trust"]["inline_stores"][0]["metadata"]["content_sha256"] == ref["content_sha256"]
    assert "BEGIN CERTIFICATE" not in str(before["config_snapshot"])  # the API never returns the raw certificates
    # the administrator changes the store: v2 replaces the Root CA by another customer's
    r = admin.post(f"/api/admin/trust-stores/{acme['id']}/versions", json={"files": files("Globex-Root-CA.crt", "Globex-Issuing-CA.crt"), "base": "empty"})
    assert r.status_code == 201 and r.json()["version"] == 2
    after = admin.get(f"/api/scan-runs/{run_acme['id']}").json()
    assert after["trust_stores"] == before["trust_stores"]                                   # the historical run is unchanged
    assert endpoints(admin.get(f"/api/scan-runs/{run_acme['id']}").json())[PORTS["full"]]["certificate"]["trust_classification"] == "PRIVATE_TRUSTED"
    # a new scan with the same profile uses the new version
    profile_id = next(p["id"] for p in operator.get("/api/profiles").json() if acme["id"] in str(p["versions"][0]["content"]))
    new_run = scan(user, operator, catalog, profile_id)
    assert new_run["trust_stores"][0]["version"] == 2
    assert endpoints(new_run)[PORTS["full"]]["certificate"]["trust_classification"] == "UNTRUSTED"
    assert endpoints(new_run)[PORTS["globex"]]["certificate"]["trust_classification"] == "PRIVATE_TRUSTED"


def test_reports_carry_the_provenance(auditor, run_globex, globex):
    metadata = auditor.get(f"/api/scan-runs/{run_globex['id']}/reports/metadata").json()
    names = [s["store_name"] for s in metadata["trust_stores"]]
    assert f"{globex['name']} (v1)" in names and "TLS Scan Public Web PKI" in names
    store = next(s for s in metadata["trust_stores"] if s["store_name"].startswith(globex["name"]))
    assert store["metadata"]["content_sha256"] == globex["content_sha256"] and store["store_type"] == "inline"
    trust = {e["endpoint_id"]: e for e in metadata["endpoint_trust"]}
    ok = trust[endpoints(run_globex)[PORTS["globex"]]["endpoint_id"]]
    assert ok["trust_classification"] == "PRIVATE_TRUSTED" and ok["trusted_by"] == [f"{globex['name']} (v1)"]
    assert "BEGIN CERTIFICATE" not in str(metadata)
    html = auditor.get(f"/api/scan-runs/{run_globex['id']}/reports/html").text
    csv = auditor.get(f"/api/scan-runs/{run_globex['id']}/reports/csv").text
    md = auditor.get(f"/api/scan-runs/{run_globex['id']}/reports/md").text
    for text in (html, csv, md):
        assert globex["name"] in text and "PRIVATE_TRUSTED" in text and "BEGIN CERTIFICATE" not in text


def test_results_api_exposes_trust_fields(auditor, run_acme):
    items = auditor.get(f"/api/results/{run_acme['id']}/endpoints").json()["items"]
    full = next(e for e in items if str(e["port"]) == PORTS["full"])
    assert full["certificate"]["trust_classification"] == "PRIVATE_TRUSTED" and full["certificate"]["trusted_by"]
    detail = auditor.get(f"/api/results/{run_acme['id']}").json()
    assert detail["trust_stores"][0]["version"] == 1
