"""DNS discovery V2 without any network or database: policy, methods and consolidation against an in-memory resolver."""
from __future__ import annotations

import asyncio

import dns.xfr
import dns.zone
import pytest

from tls_scan_app.services.dns_discovery import methods, policy
from tls_scan_app.services.dns_discovery.model import Answer, LookupFailure
from tls_scan_app.services.dns_discovery.runner import DEFAULT_OPTIONS, discover_async, failure_message


class FakeLookup:
    """Dictionary-driven resolver: {(name, type): [values] | LookupFailure}. Unknown names do not exist."""

    def __init__(self, records: dict, canonical: dict | None = None) -> None:
        self.records, self.canonical, self.queries = records, canonical or {}, 0

    async def query(self, name: str, rdtype: str) -> Answer:
        self.queries += 1
        value = self.records.get((name.lower(), rdtype))
        if isinstance(value, LookupFailure):
            raise value
        if value is None:
            raise LookupFailure("nxdomain" if not any(k[0] == name.lower() for k in self.records) else "nodata")
        return Answer(list(value), self.canonical.get(name.lower(), ""))


ZONE = {
    ("example.org", "NS"): ["ns1.example.org."], ("ns1.example.org", "A"): ["192.0.2.53"],
    ("example.org", "A"): ["192.0.2.1"], ("example.org", "MX"): ["10 mail.example.org.", "20 mx.partner.net."],
    ("example.org", "SOA"): ["ns1.example.org. h.example.org. 1 2 3 4 5"], ("example.org", "TXT"): ['"v=spf1 include:bad.example.com -all"'],
    ("mail.example.org", "A"): ["192.0.2.25"], ("mx.partner.net", "A"): ["198.51.100.25"],
    ("_ldap._tcp.example.org", "SRV"): ["0 0 389 dc1.example.org."], ("dc1.example.org", "A"): ["192.0.2.60"],
    ("www.example.org", "A"): ["192.0.2.10"], ("www.example.org", "AAAA"): ["2001:db8::10"], ("vpn.example.org", "A"): ["192.0.2.20"],
}
ZONE_TEXT = """
$ORIGIN example.org.
@ 3600 IN SOA ns1 hostmaster 1 7200 3600 1209600 3600
@ 3600 IN NS ns1
@ 3600 IN MX 10 mail
ns1 3600 IN A 192.0.2.53
mail 3600 IN A 192.0.2.25
www 3600 IN A 192.0.2.10
old 3600 IN CNAME www
_sip._tcp 3600 IN SRV 0 0 5060 www
* 3600 IN A 192.0.2.99
note 3600 IN TXT "hello"
"""


def run(domain="example.org", options=None, lookup=None, settings=None, **kwargs):
    opts = {**DEFAULT_OPTIONS, **(options or {})}
    return asyncio.run(discover_async(domain, opts, settings or {"ct_enabled": True}, lookup=lookup or FakeLookup(ZONE), **kwargs))


def names(result, scope=True):
    return {o["fqdn"]: o for o in result["observations"] if o["in_scope"] or not scope}


@pytest.fixture
def transfer_ok(monkeypatch):
    zone = dns.zone.from_text(ZONE_TEXT, origin="example.org.", relativize=True)
    monkeypatch.setattr(methods, "run_transfer", lambda *a, **k: zone)


# ---------- policy ----------
@pytest.mark.parametrize("value,expected", [("10.0.0.53", ("10.0.0.53", 53)), ("10.0.0.53:5353", ("10.0.0.53", 5353)), ("[2001:db8::53]:5353", ("2001:db8::53", 5353)), ("2001:db8::53", ("2001:db8::53", 53))])
def test_server_parsing(value, expected):
    assert policy.parse_server(value) == expected


@pytest.mark.parametrize("value", ["", "dns.example.org", "127.0.0.1", "::1", "169.254.169.254", "100.100.100.200", "fd00:ec2::254", "224.0.0.1", "0.0.0.0", "10.0.0.1:0", "10.0.0.1:70000", "10.0.0.1:x", "10.0.0.1 ; rm"])
def test_sensitive_or_malformed_servers_are_refused(value):
    with pytest.raises(policy.DiscoveryError):
        policy.parse_server(value)


def test_a_server_must_be_declared_by_an_administrator():
    settings = {"allowed_servers": ["10.0.0.53", "10.0.0.54:5353"]}
    assert policy.authorized_server("10.0.0.53", settings) == ("10.0.0.53", 53)
    assert policy.authorized_server("10.0.0.54:5353", settings) == ("10.0.0.54", 5353)
    for refused in ("10.0.0.54", "10.0.0.55", "10.0.0.53:5353"):
        with pytest.raises(policy.DiscoveryError, match="not authorised"):
            policy.authorized_server(refused, settings)
    with pytest.raises(policy.DiscoveryError):
        policy.authorized_server("10.0.0.53", {})


def test_admin_settings_validation():
    assert policy.validate_settings({"allowed_servers": [" 10.0.0.53 ", "10.0.0.53:53", ""], "ct_enabled": False}) == {"allowed_servers": ["10.0.0.53:53"], "ct_enabled": False, "recent_scan_days": 7}
    for bad in ({"allowed_servers": "10.0.0.1"}, {"allowed_servers": ["127.0.0.1"]}, {"ct_enabled": "yes"}, {"recent_scan_days": 0}, {"recent_scan_days": True}, {"other": 1}, {"allowed_servers": ["1.1.1.1"] * 51}):
        with pytest.raises(policy.DiscoveryError):
            policy.validate_settings(bad)


@pytest.mark.parametrize("domain,public", [("example.org", True), ("sub.example.com", True), ("client.local", False), ("corp.internal", False), ("x.test", False), ("intranet.lan", False), ("home.arpa", False), ("localhost", False)])
def test_internal_domains_are_never_public(domain, public):
    assert policy.is_public_domain(domain) is public


def test_reverse_addresses_are_bounded():
    assert policy.expand_reverse(["192.0.2.1", "192.0.2.0/30"])[:2] == ["192.0.2.1", "192.0.2.0"]
    assert len(policy.expand_reverse(["10.0.0.0/24"])) == 256
    for bad in (["10.0.0.0/16"], ["2001:db8::/64"], ["127.0.0.1"], ["nope"], ["10.0.0.0/24", "10.0.1.0/24"]):
        with pytest.raises(policy.DiscoveryError):
            policy.expand_reverse(bad)


def test_custom_dictionary_is_validated():
    assert policy.clean_words(["WWW", "mail ", "www", ""]) == ["www", "mail"]
    for bad in (["a b"], ["-x"], ["a.b"], ["x" * 64], ["w"] * 5001):
        with pytest.raises(policy.DiscoveryError):
            policy.clean_words(bad)


@pytest.mark.parametrize("name,expected", [("WWW.Example.org.", "www.example.org"), ("*.example.org", None), ("_sip._tcp.example.org", None), ("localhost", None), ("a..b", None), ("-a.example.org", None)])
def test_host_names(name, expected):
    assert policy.valid_host(name) == expected


# ---------- classic resolution ----------
def test_classic_resolution_keeps_roles_and_never_treats_txt_as_a_target():
    result = run(options={"methods": ["dns"]})
    found = names(result, scope=False)
    assert found["example.org"]["roles"] == ["apex"] and found["example.org"]["ips"] == ["192.0.2.1"]
    assert "mx" in found["mail.example.org"]["roles"] and found["mail.example.org"]["resolved"] is True
    assert found["dc1.example.org"]["roles"] == ["srv"]
    assert found["mx.partner.net"]["in_scope"] is False                     # kept for information, outside the perimeter
    assert all("spf" not in n and "bad.example.com" not in n for n in found)  # TXT content is never a name to discover
    assert result["methods"]["dns"]["status"] in ("done", "partial") and result["methods"]["dns"]["info"]["txt_count"] == 1
    assert "mx.partner.net" not in {h["fqdn"] for h in result["hosts"]}     # legacy host list: in-scope only


def test_nxdomain_ends_the_discovery_with_a_clear_error():
    with pytest.raises(policy.DiscoveryError, match="does not exist"):
        run("missing.example", lookup=FakeLookup({}))


def test_dns_failure_is_explicit_not_a_hang():
    lookup = FakeLookup({("example.org", "NS"): LookupFailure("timeout"), ("example.org", "A"): LookupFailure("timeout")})
    for rdtype in ("AAAA", "MX", "SOA", "TXT"):
        lookup.records[("example.org", rdtype)] = LookupFailure("timeout")
    result = run(lookup=lookup)
    assert result["methods"]["dns"]["status"] == "failed" and result["methods"]["axfr"]["status"] == "skipped"
    assert result["observations"] == []
    assert "No DNS method succeeded" in failure_message(result)


# ---------- zone transfer ----------
def test_accepted_transfer_yields_names_and_a_per_server_report(transfer_ok):
    result = run(options={"methods": ["axfr"]})
    assert result["transfer_possible"] is True
    server = result["nameservers"][0]
    assert server["status"] == "transferred" and server["address"] == "192.0.2.53" and server["source"] == "ns" and server["records"] >= 3
    found = names(result)
    assert {"www.example.org", "old.example.org", "mail.example.org", "ns1.example.org"} <= set(found)
    assert not any("*" in n or "_" in n for n in found)                      # wildcards and service labels dropped
    assert found["www.example.org"]["sources"] == ["axfr"]
    assert result["security"] == []                                          # 192.0.2.53 is documentation space, not a public server in the sense of the finding


def test_refused_transfer_is_a_normal_result_and_other_methods_still_work(monkeypatch):
    def refuse(*a, **k):
        raise dns.xfr.TransferError(5)

    monkeypatch.setattr(methods, "run_transfer", refuse)
    lookup = FakeLookup({**ZONE, ("mail.example.org", "A"): ["192.0.2.25"]})
    result = run(options={"methods": ["dns", "axfr", "dictionary"]}, lookup=lookup)
    assert result["transfer_possible"] is False and result["nameservers"][0]["status"] == "refused"
    assert result["methods"]["axfr"]["status"] == "done"
    assert "www.example.org" in names(result) and "vpn.example.org" in names(result)   # found by DNS and by the dictionary


@pytest.mark.parametrize("exception,status", [(TimeoutError(), "timeout"), (OSError("unreachable"), "unreachable"), (MemoryError(), "too_large"), (RuntimeError("boom"), "error")])
def test_transfer_failures_are_classified(monkeypatch, exception, status):
    def fail(*a, **k):
        raise exception

    monkeypatch.setattr(methods, "run_transfer", fail)
    assert run(options={"methods": ["axfr"]})["nameservers"][0]["status"] == status


def test_explicit_servers_are_asked_and_results_deduplicated(monkeypatch, transfer_ok):
    asked = []
    original = methods.run_transfer

    def spy(transfer, address, port, *a, **k):
        asked.append((address, port))
        return original(transfer, address, port, *a, **k)

    monkeypatch.setattr(methods, "run_transfer", spy)
    result = run(options={"methods": ["axfr"], "axfr_servers": ["10.10.0.10:53", "10.10.0.11:5353", "192.0.2.53:53"]})
    assert asked == [("192.0.2.53", 53), ("10.10.0.10", 53), ("10.10.0.11", 5353)]     # 192.0.2.53 asked once although listed twice
    assert [s["source"] for s in result["nameservers"]] == ["ns", "explicit", "explicit"]
    assert len([o for o in result["observations"] if o["fqdn"] == "www.example.org"]) == 1
    assert names(result)["www.example.org"]["source_details"]["axfr"] == ["10.10.0.10", "10.10.0.11", "192.0.2.53"]


def test_sensitive_servers_are_never_queried(monkeypatch, transfer_ok):
    lookup = FakeLookup({**ZONE, ("example.org", "NS"): ["ns1.example.org."], ("ns1.example.org", "A"): ["169.254.169.254"]})
    result = run(options={"methods": ["axfr"]}, lookup=lookup)
    assert result["nameservers"][0]["status"] == "skipped" and result["transfer_possible"] is False


def test_open_transfer_on_a_public_server_is_reported_as_a_security_observation(transfer_ok):
    lookup = FakeLookup({**ZONE, ("ns1.example.org", "A"): ["198.18.0.53"]})
    assert run(options={"methods": ["axfr"]}, lookup=lookup)["security"] == []     # benchmarking range: not global
    lookup = FakeLookup({**ZONE, ("ns1.example.org", "A"): ["8.8.4.4"]})
    security = run(options={"methods": ["axfr"]}, lookup=lookup)["security"]
    assert security and security[0]["kind"] == "axfr_open"


def test_transfer_record_budget(monkeypatch):
    class Message:
        def __init__(self, n):
            self.answer = [[0] * n]

    gen = (Message(30000) for _ in range(3))
    with pytest.raises(MemoryError):
        list(methods.bounded_transfer(gen, methods.MAX_AXFR_RRSETS))


# ---------- dictionary ----------
def test_dictionary_finds_names_and_ignores_unknown_ones():
    result = run(options={"methods": ["dictionary"]})
    assert set(names(result)) == {"www.example.org", "vpn.example.org", "mail.example.org", "ns1.example.org"}   # the words of the list that exist
    assert result["methods"]["dictionary"]["found"] == 4 and names(result)["www.example.org"]["ips"] == ["192.0.2.10", "2001:db8::10"]


def test_wildcard_answers_do_not_fill_the_inventory(monkeypatch):
    class Wild(FakeLookup):
        async def query(self, name, rdtype):
            if name.endswith(".wild.test") and name.split(".")[0] not in ("www", "api") and rdtype == "A":
                self.queries += 1
                return Answer(["192.0.2.99"])
            return await super().query(name, rdtype)

    lookup = Wild({("www.wild.test", "A"): ["192.0.2.20"], ("api.wild.test", "A"): ["192.0.2.21"], ("wild.test", "NS"): ["ns.wild.test."]})
    result = run("wild.test", options={"methods": ["dictionary"]}, lookup=lookup)
    assert set(names(result)) == {"www.wild.test", "api.wild.test"}
    assert result["methods"]["dictionary"]["wildcard"] is True and result["methods"]["dictionary"]["wildcard_filtered"] > 10


def test_dictionary_sizes_and_custom_list():
    assert 50 < len(methods.load_words("small", [])) < 120
    assert len(methods.load_words("extended", [])) > 300
    assert set(methods.load_words("small", [])) <= set(methods.load_words("extended", []))
    result = run(options={"methods": ["dictionary"], "dictionary": "custom", "custom_words": ["vpn", "nothere"]})
    assert set(names(result)) == {"vpn.example.org"}


# ---------- Certificate Transparency ----------
def test_ct_names_are_scoped_resolved_and_history_is_not_presented_as_active():
    sent = []

    def fetch(domain):
        sent.append(domain)
        return ["www.example.org", "*.example.org", "old-shop.example.org", "vpn.example.org", "other.com", "deep.sub.example.org"]

    result = run(options={"methods": ["ct"]}, ct_fetch=fetch)
    assert sent == ["example.org"]                                            # only the public domain name leaves
    found = names(result)
    assert set(found) == {"www.example.org", "old-shop.example.org", "vpn.example.org", "deep.sub.example.org"}   # wildcard and foreign names dropped
    assert found["www.example.org"]["resolved"] is True and "ct_historical" not in found["www.example.org"]["notes"]
    assert "ct_historical" in found["old-shop.example.org"]["notes"] and not found["old-shop.example.org"]["ips"]
    assert "wildcard certificate name" in result["methods"]["ct"]["detail"]


def test_internal_domains_are_never_sent_to_an_external_service():
    called = []
    result = run("client.local", options={"methods": ["ct"]}, lookup=FakeLookup({("client.local", "NS"): ["ns.client.local."]}), ct_fetch=lambda d: called.append(d) or [])
    assert called == [] and result["methods"]["ct"]["status"] == "skipped" and "never sent" in result["methods"]["ct"]["detail"]


def test_ct_can_be_disabled_by_the_administrator_and_its_failure_is_not_fatal():
    called = []
    result = run(options={"methods": ["ct"]}, settings={"ct_enabled": False}, ct_fetch=lambda d: called.append(d) or [])
    assert called == [] and result["methods"]["ct"]["status"] == "skipped"

    def broken(domain):
        raise OSError("service down")

    result = run(options={"methods": ["dns", "ct"]}, ct_fetch=broken)
    assert result["methods"]["ct"]["status"] == "failed" and "unavailable" in result["methods"]["ct"]["detail"]
    assert result["methods"]["dns"]["status"] in ("done", "partial") and "www.example.org" not in names(result)  # DNS results are unaffected
    assert "mail.example.org" in names(result)


# ---------- reverse DNS ----------
def test_reverse_flags_mismatches_and_out_of_scope_names():
    lookup = FakeLookup({
        ("10.2.0.192.in-addr.arpa", "PTR"): ["www.example.org."], ("20.2.0.192.in-addr.arpa", "PTR"): ["vpn.example.org."],
        ("22.2.0.192.in-addr.arpa", "PTR"): ["stranger.other.net."], ("www.example.org", "A"): ["192.0.2.10"], ("vpn.example.org", "A"): ["192.0.2.99"],
        ("stranger.other.net", "A"): ["192.0.2.22"],
    })
    result = run(options={"methods": ["reverse"], "reverse_addresses": ["192.0.2.10", "192.0.2.20", "192.0.2.22", "192.0.2.30"]}, lookup=lookup)
    found = names(result, scope=False)
    assert found["www.example.org"]["notes"] == [] and found["www.example.org"]["resolved"] is True
    assert "ptr_mismatch" in found["vpn.example.org"]["notes"]               # PTR and forward resolution disagree
    assert found["stranger.other.net"]["in_scope"] is False                  # a PTR does not widen the perimeter
    assert result["methods"]["reverse"]["detail"].endswith("1 PTR/forward mismatch(es)")


# ---------- orchestration ----------
def test_one_failing_method_does_not_stop_the_others(monkeypatch):
    async def boom(ctx):
        raise RuntimeError("bug")

    monkeypatch.setitem(methods.METHOD_FUNCTIONS, "dictionary", boom)
    result = run(options={"methods": ["dns", "dictionary"]})
    assert result["methods"]["dictionary"]["status"] == "failed" and result["methods"]["dns"]["status"] in ("done", "partial")
    assert "mail.example.org" in names(result)


def test_cancellation_and_deadline_keep_partial_results():
    calls = {"n": 0}

    def stop():
        calls["n"] += 1
        return calls["n"] > 3

    result = run(options={"methods": ["dns", "dictionary", "ct"], "dictionary": "extended"}, should_stop=stop, ct_fetch=lambda d: [])
    assert result["partial"] is True and result["stopped"] == "cancelled"
    assert any(r["status"] == "skipped" for r in result["methods"].values()) or result["methods"]["dictionary"]["status"] == "partial"
    result = run(options={"methods": ["dictionary"], "max_duration_seconds": -1})
    assert result["partial"] is True and result["stopped"] == "deadline"


def test_progress_is_reported_with_totals_only_when_known():
    seen = []
    run(options={"methods": ["dictionary"]}, progress=seen.append)
    dictionary_steps = [p for p in seen if p.get("phase") == "dictionary" and "done" in p]
    assert dictionary_steps and dictionary_steps[-1]["done"] == dictionary_steps[-1]["total"] == len(methods.load_words("small", []))
    assert all("total" not in p for p in seen if p.get("phase") == "dns")


def test_names_are_capped():
    collector = methods.Collector("example.org")
    for i in range(policy.MAX_NAMES + 10):
        collector.add(f"h{i}.example.org", "dictionary")
    assert len(collector.items) == policy.MAX_NAMES and collector.truncated is True


def test_default_call_behaves_like_before():
    assert DEFAULT_OPTIONS["methods"] == ["dns", "axfr"] and policy.LEGACY_METHODS == ("dns", "axfr")


def test_ct_falls_back_to_a_second_provider_and_sends_nothing_else(monkeypatch):
    urls = []

    class Response:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return self.body

    class Opener:
        def open(self, request, timeout=0):
            urls.append(request.full_url)
            if "crt.sh" in request.full_url:
                import urllib.error

                raise urllib.error.HTTPError(request.full_url, 502, "bad gateway", {}, None)
            return Response(b'[{"dns_names": ["www.example.org", "*.example.org"]}, {"dns_names": ["API.example.org"]}]')

    monkeypatch.setattr(methods.urllib.request, "build_opener", lambda *handlers: Opener())
    assert methods.fetch_ct("example.org") == ["*.example.org", "api.example.org", "www.example.org"]
    assert len(urls) == 2 and all("example.org" in u for u in urls) and urls[0].startswith("https://crt.sh/")

    class Down(Opener):
        def open(self, request, timeout=0):
            import urllib.error

            raise urllib.error.HTTPError(request.full_url, 503, "down", {}, None)

    monkeypatch.setattr(methods.urllib.request, "build_opener", lambda *handlers: Down())
    with pytest.raises(OSError, match="crt.sh: HTTPError 503; certspotter: HTTPError 503"):
        methods.fetch_ct("example.org")
