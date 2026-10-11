"""DNS discovery (name servers + zone-transfer attempt): pure logic, then the API and the worker."""
from __future__ import annotations

import dns.zone
import pytest

from conftest import wait_for
from tls_scan_app.services.dns_discovery import DiscoveryError, hosts_from_zone, normalize_domain, server_allowed

ZONE = """
$ORIGIN example.org.
@ 3600 IN SOA ns1 hostmaster 1 7200 3600 1209600 3600
@ 3600 IN NS ns1
@ 3600 IN A 192.0.2.1
www 3600 IN A 192.0.2.10
www 3600 IN AAAA 2001:db8::10
mail 3600 IN CNAME www
_sip._tcp 3600 IN SRV 0 0 5060 www
* 3600 IN A 192.0.2.99
txt-only 3600 IN TXT "v=spf1 -all"
"""


class TestPureLogic:
    def test_hosts_from_zone_keeps_hosts_and_drops_wildcards_services_and_non_hosts(self):
        zone = dns.zone.from_text(ZONE, origin="example.org.", relativize=True)
        hosts = {h["fqdn"]: h for h in hosts_from_zone(zone, "example.org")}
        assert set(hosts) == {"example.org", "www.example.org", "mail.example.org"}
        assert hosts["www.example.org"]["types"] == ["A", "AAAA"]
        assert hosts["mail.example.org"]["types"] == ["CNAME"]

    @pytest.mark.parametrize("value,expected", [("Example.ORG.", "example.org"), (" a.b.example.org ", "a.b.example.org")])
    def test_domain_is_normalised(self, value, expected):
        assert normalize_domain(value) == expected

    @pytest.mark.parametrize("value", ["", "localhost", "192.0.2.1", "bad_label.example.org", "-a.example.org", "a..b", "x" * 64 + ".org", "a b.org"])
    def test_invalid_domains_are_refused(self, value):
        with pytest.raises(DiscoveryError):
            normalize_domain(value)

    @pytest.mark.parametrize("address,allowed", [("127.0.0.1", False), ("169.254.169.254", False), ("::1", False), ("224.0.0.1", False),
                                                   ("0.0.0.0", False), ("192.0.2.53", True), ("10.0.0.53", True), ("2001:db8::53", True)])
    def test_local_servers_are_never_queried(self, address, allowed):
        assert server_allowed(address) is allowed


class TestApi:
    def test_roles(self, auditor, user, operator):
        body = {"domain": "example.org", "authorized": True}
        assert auditor.post("/api/targets/discover", json=body).status_code == 403
        assert user.post("/api/targets/discover", json=body).status_code == 403

    def test_authorisation_statement_is_required(self, operator):
        assert operator.post("/api/targets/discover", json={"domain": "example.org"}).status_code == 400

    def test_invalid_domain_is_refused(self, operator):
        assert operator.post("/api/targets/discover", json={"domain": "192.0.2.1", "authorized": True}).status_code == 422

    def test_unknown_domain_ends_in_a_clear_failure_and_is_private(self, operator, user2, admin):
        r = operator.post("/api/targets/discover", json={"domain": "no-such-domain.invalid", "authorized": True})
        assert r.status_code == 202, r.text
        job = r.json()
        assert operator.post("/api/targets/discover", json={"domain": "other.invalid", "authorized": True}).status_code in (202, 409)
        done = wait_for(lambda: (j := operator.get(f"/api/targets/discover/{job['id']}").json())["status"] in ("done", "failed") and j, timeout=90)
        assert done["status"] == "failed" and done["error"]
        assert admin.get(f"/api/targets/discover/{job['id']}").status_code == 200
        assert user2.get(f"/api/targets/discover/{job['id']}").status_code in (403, 404)
        events = admin.get("/api/admin/audit", params={"action": "target.discover"}).json()
        assert any(e["action"].startswith("target.discover") for e in (events["items"] if isinstance(events, dict) else events))
