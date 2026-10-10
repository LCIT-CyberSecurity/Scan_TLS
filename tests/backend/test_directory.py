"""Directory connectors: LDAP (real OpenLDAP container) and Entra ID through Graph (mock server only)."""
from __future__ import annotations

import uuid

import httpx
import pytest
from ldap3 import Connection, Server

from conftest import API, Api, wait_for

LDAP_BASE = "dc=example,dc=org"
ADMIN_DN, ADMIN_PW = f"cn=admin,{LDAP_BASE}", "ldap-test-admin-pw"


@pytest.fixture(scope="module")
def ldap_people():
    def connect():
        c = Connection(Server("openldap", port=389), user=ADMIN_DN, password=ADMIN_PW)
        assert c.bind()
        return c

    wait_for(lambda: _try(connect), 60)
    c = connect()
    c.add(f"ou=people,{LDAP_BASE}", "organizationalUnit")
    for uid, cn, mail in (("jdoe", "John Doe", "john.doe@example.org"), ("asmith", "Alice Smith", "alice.smith@example.org")):
        c.add(f"uid={uid},ou=people,{LDAP_BASE}", "inetOrgPerson", {"cn": cn, "sn": cn.split()[1], "mail": mail, "uid": uid})
    c.unbind()


def _try(fn):
    try:
        fn()
        return True
    except Exception:  # noqa: BLE001
        return False


def ldap_cfg(**over):
    return {"kind": "ldap", "ldap": {"server_url": "ldap://openldap:389", "bind_dn": ADMIN_DN, "base_dn": f"ou=people,{LDAP_BASE}",
                                     "user_filter": "(objectClass=inetOrgPerson)", "id_attribute": "uid", **over}}


def test_ldap_diagnostics_search_and_errors(admin, ldap_people):
    assert admin.put("/api/admin/directory", json=ldap_cfg()).status_code == 200
    steps = admin.post("/api/admin/directory/test").json()
    assert [(s["step"], s["status"]) for s in steps] == [("dns", "ok"), ("connect+bind", "ok"), ("search", "ok")]
    found = admin.get("/api/admin/directory/search", params={"q": "smith"}).json()
    assert [p["email"] for p in found] == ["alice.smith@example.org"] and found[0]["provisioned"] is False
    assert admin.get("/api/admin/directory/search", params={"q": "a"}).status_code == 422
    # LDAP filter injection is neutralised
    assert admin.get("/api/admin/directory/search", params={"q": "*)(uid=*"}).json() == []

    admin.put("/api/admin/directory", json=ldap_cfg(base_dn=f"ou=nowhere,{LDAP_BASE}"))
    steps = admin.post("/api/admin/directory/test").json()
    assert steps[-1]["step"] == "search" and steps[-1]["status"] == "fail" and "base DN" in steps[-1]["detail"]
    admin.put("/api/admin/directory", json=ldap_cfg(bind_dn=f"cn=nobody,{LDAP_BASE}"))
    steps = admin.post("/api/admin/directory/test").json()
    assert steps[-1]["status"] == "fail" and "bind" in steps[-1]["detail"].lower()
    admin.put("/api/admin/directory", json=ldap_cfg(server_url="ldap://no-such-host.invalid:389"))
    assert admin.post("/api/admin/directory/test").json()[0] == {"step": "dns", "status": "fail", "detail": admin.post("/api/admin/directory/test").json()[0]["detail"]}


def test_ldaps_untrusted_certificate_is_explained(admin, ldap_people):
    admin.put("/api/admin/directory", json=ldap_cfg(server_url="ldaps://openldap:636"))
    steps = admin.post("/api/admin/directory/test").json()
    assert steps[-1]["status"] == "fail" and "not trusted" in steps[-1]["detail"], steps
    admin.put("/api/admin/directory", json=ldap_cfg(server_url="ldaps://openldap:636", tls_verify=False))
    steps = admin.post("/api/admin/directory/test").json()
    assert all(s["status"] == "ok" for s in steps), steps


def test_entra_connector_against_graph_mock(admin):
    entra = {"tenant_id": "contoso-test", "client_id": "app-dir"}
    admin.put("/api/admin/directory", json={"kind": "entra", "entra": entra})
    steps = admin.post("/api/admin/directory/test").json()
    assert [(s["step"], s["status"]) for s in steps] == [("token", "ok"), ("read-users", "ok")]
    people = admin.get("/api/admin/directory/search", params={"q": "directory"}).json()
    assert {p["email"] for p in people} == {"alice.directory@contoso.example", "bob.directory@contoso.example"}  # UPN used when mail is empty
    admin.put("/api/admin/directory", json={"kind": "entra", "entra": {**entra, "tenant_id": "denied"}})
    steps = admin.post("/api/admin/directory/test").json()
    assert steps[-1]["status"] == "fail" and "User.Read.All" in steps[-1]["detail"]


def test_provision_then_sso_adopts_the_account_with_its_role(admin, operator):
    assert operator.get("/api/admin/directory").status_code == 403
    email = f"preprov-{uuid.uuid4().hex[:6]}@sso.example.com"
    assert admin.post("/api/admin/directory/provision", json={"email": email, "role": "OPERATOR"}).status_code == 201
    assert admin.post("/api/admin/directory/provision", json={"email": email, "role": "USER"}).status_code == 409
    from test_sso import sso_login

    me = sso_login(email).get("/api/auth/me").json()["user"]
    assert me["email"] == email and me["role"] == "OPERATOR"  # role chosen in advance, not the default USER
    assert len([u for u in admin.get("/api/admin/users").json() if u["email"] == email]) == 1  # adopted, not duplicated
