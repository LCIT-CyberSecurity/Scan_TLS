from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import pytest
from orion_app.services.dns_discovery.lookalike import (
    MAX_CANDIDATES,
    generate_candidates,
    observe_candidates,
)
from orion_app.services.dns_discovery.model import Answer, LookupFailure
from orion_app.services.dns_discovery.policy import DiscoveryError


def test_generator_is_bounded_deterministic_and_marks_reason() -> None:
    first = generate_candidates("example.com", tlds=["net", "org"], max_candidates=MAX_CANDIDATES)
    second = generate_candidates("example.com", tlds=["net", "org"], max_candidates=MAX_CANDIDATES)

    assert first == second
    assert len(first) <= MAX_CANDIDATES
    assert all(item["domain"] != "example.com" for item in first)
    assert {"missing-character", "repeated-character", "transposition", "substitution", "alternate-tld"} <= {
        technique for item in first for technique in item["techniques"].split(",")
    }
    assert all(isinstance(item["score"], float) and 0 <= item["score"] <= 1 for item in first)


def test_generator_punycode_encodes_homoglyphs_and_applies_exclusions() -> None:
    candidates = generate_candidates("example.com", exclusions=["examp1e.com"], max_candidates=100)
    names = {item["domain"] for item in candidates}

    assert "xn--examp1e-9za.com" in names or any(name.startswith("xn--") for name in names)
    assert "examp1e.com" not in names
    assert all(name.isascii() for name in names)


def test_generator_rejects_non_public_domain_bad_tld_and_unbounded_caps() -> None:
    with pytest.raises(DiscoveryError, match="public domains"):
        generate_candidates("internal.local")
    with pytest.raises(DiscoveryError, match="TLD"):
        generate_candidates("example.com", tlds=["com/evil"])
    with pytest.raises(DiscoveryError, match="Candidate limit"):
        generate_candidates("example.com", max_candidates=MAX_CANDIDATES + 1)


class FakeLookup:
    queries = 0

    async def query(self, name: str, rdtype: str) -> Answer:
        self.queries += 1
        if rdtype == "A" and (name == "examp1e.com" or name.startswith("orion-") or name.endswith(".com")):
            return Answer(["203.0.113.9"])
        raise LookupFailure("nxdomain")


def test_observer_distinguishes_dns_ct_rdap_and_never_labels_malicious() -> None:
    candidates = [{"domain": "examp1e.com", "score": 0.8, "techniques": "substitution"},
                  {"domain": "nonexistent-example.net", "score": 0.5, "techniques": "alternate-tld"}]
    ct_calls, rdap_calls = [], []
    async def ct(domain: str) -> list[str]:
        ct_calls.append(domain)
        return [f"www.{domain}"]
    async def rdap(domain: str) -> bool:
        rdap_calls.append(domain)
        return True
    lookup = FakeLookup()
    rows = asyncio.run(observe_candidates(candidates, lookup=lookup, ct_fetch=ct, rdap_fetch=rdap, max_ct=1, max_rdap=1))

    assert rows[0]["dns_status"] == "resolved"
    assert rows[0]["status"] == "suspect_to_review"
    assert rows[0]["ct_status"] == "observed"
    assert rows[0]["rdap_status"] == "registered"
    assert rows[0]["malicious"] is False
    assert rows[1]["dns_status"] == "not_observed"
    assert rows[1]["ct_status"] == rows[1]["rdap_status"] == "not_checked"
    assert ct_calls == ["examp1e.com"] and rdap_calls == ["examp1e.com"]
    assert lookup.queries == 10


def test_run_monitor_identifies_wildcard_dns_and_keeps_it_informational() -> None:
    from orion_app.services.dns_discovery.lookalike import run_monitor

    rows = asyncio.run(run_monitor("example.com", {"max_candidates": 20, "tlds": [], "ct_enabled": False}, lookup=FakeLookup()))

    assert rows["sources"] == {"dns": True, "ct": False, "rdap": False}
    assert rows["generated"] <= 20
    assert any(row.get("wildcard") for row in rows["observations"])
    assert all(row["malicious"] is False for row in rows["observations"] if "malicious" in row)


def test_monitor_cancellation_stops_queries_and_reports_partial_observations() -> None:
    from orion_app.services.dns_discovery.lookalike import run_monitor

    lookup = FakeLookup()
    result = asyncio.run(run_monitor("example.com", {"max_candidates": 5}, lookup=lookup, should_stop=lambda: True))
    assert result["partial"] is True
    assert result["observations"]
    assert all(item["status"] == "cancelled" for item in result["observations"])
    assert lookup.queries == 0


def test_scheduler_queues_only_an_enabled_owned_admin_monitor(monkeypatch) -> None:
    from orion_app.models import DnsDiscovery, DnsLookalikeMonitor, Role, User
    from orion_app.scheduler import scheduler

    owner_id, monitor_id = uuid.uuid4(), uuid.uuid4()
    owner = SimpleNamespace(id=owner_id, role=Role.ADMIN, active=True)
    monitor = SimpleNamespace(id=monitor_id, owner_id=owner_id, domain="example.com", enabled=True, deleted_at=None)

    class FakeDb:
        def __init__(self, *, enabled: bool):
            self.enabled = enabled
            self.added = []

        def get(self, model, key):
            if model is User:
                return owner
            if model is DnsLookalikeMonitor:
                return monitor if self.enabled else SimpleNamespace(**{**monitor.__dict__, "enabled": False})
            return None

        def scalar(self, _statement):
            return None

        def add(self, row):
            self.added.append(row)

        def flush(self):
            pass

    monkeypatch.setattr(scheduler.audit, "record", lambda *args, **kwargs: None)
    schedule = SimpleNamespace(id=uuid.uuid4(), owner_id=owner_id, task_config={"authorized": True, "domain": "example.com",
                                                                "options": {"lookalike_monitor_id": str(monitor_id)}})
    enabled_db = FakeDb(enabled=True)
    outcome = scheduler._fire_dns(enabled_db, schedule)
    assert outcome[0] == "triggered"
    assert len(enabled_db.added) == 1
    assert isinstance(enabled_db.added[0], DnsDiscovery)
    assert enabled_db.added[0].options == {"lookalike_monitor_id": str(monitor_id)}

    disabled_db = FakeDb(enabled=False)
    outcome = scheduler._fire_dns(disabled_db, schedule)
    assert outcome[0] == "error" and not disabled_db.added


def test_disabled_queued_monitor_is_rejected_by_worker_before_any_dns_query() -> None:
    from orion_app.models import DnsDiscovery, DnsLookalikeMonitor
    from orion_app.services.dns_discovery.runner import process_next

    monitor_id = uuid.uuid4()
    row = DnsDiscovery(domain="example.com", status="queued", options={"lookalike_monitor_id": str(monitor_id)})
    row.id = uuid.uuid4()
    row.cancel_requested = False
    monitor = SimpleNamespace(enabled=False, deleted_at=None)

    class FakeDb:
        def __init__(self):
            self.queries = 0

        def execute(self, _statement):
            self.queries += 1
            if self.queries == 1:
                return SimpleNamespace(scalars=lambda: [])
            return SimpleNamespace(scalar_one_or_none=lambda: row)

        def get(self, model, _key):
            return monitor if model is DnsLookalikeMonitor else row

        def commit(self):
            pass

    class NoNetworkLookup:
        queries = 0

        async def query(self, *_args):
            self.queries += 1
            raise AssertionError("disabled monitor must not query DNS")

    db, lookup = FakeDb(), NoNetworkLookup()
    assert process_next(db, lookup=lookup) is True
    assert row.status == "failed" and row.error == "monitor disabled before execution"
    assert lookup.queries == 0


def test_monitor_configuration_requires_authorisation_and_keeps_optional_sources_off() -> None:
    from orion_app.api.catalog import LookalikeMonitorBody, _lookalike_options

    with pytest.raises(DiscoveryError, match="Confirm that you are authorised"):
        _lookalike_options(LookalikeMonitorBody(domain="example.com"), {"ct_enabled": True})
    domain, options = _lookalike_options(LookalikeMonitorBody(domain="example.com", authorized=True), {"ct_enabled": True})
    assert domain == "example.com"
    assert options["ct_enabled"] is False and options["notifications_enabled"] is False


def test_paused_monitor_does_not_generate_candidates_until_enabled(monkeypatch) -> None:
    from orion_app.api import catalog

    calls = []
    monkeypatch.setattr(catalog, "generate_candidates", lambda *args, **kwargs: calls.append((args, kwargs)))
    paused = catalog.LookalikeMonitorBody(domain="example.com", authorized=True)
    catalog._lookalike_options(paused, {})
    assert calls == []

    enabled = catalog.LookalikeMonitorBody(domain="example.com", authorized=True, enabled=True)
    catalog._lookalike_options(enabled, {})
    assert len(calls) == 1
