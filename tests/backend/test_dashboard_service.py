"""Dashboard aggregations on an in-memory database: exact rates, deduplication, partial data, policies, certificates, trend."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from tls_scan_app.database import Base
from tls_scan_app.models import RunEndpoint, RunFinding, ScanDefinition, ScanRun
from tls_scan_app.services import dashboard

NOW = datetime.now(UTC)


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def definition(db, name="scan") -> uuid.UUID:
    d = ScanDefinition(id=uuid.uuid4(), name=name, profile_id=uuid.uuid4(), policy_mode="strict_all")
    db.add(d)
    db.flush()
    return d.id


def run(db, definition_id, *, age_days=0, policy=("P", 1), fingerprint="f1", status="completed", endpoints=(), findings=(), summary=None) -> ScanRun:
    r = ScanRun(id=uuid.uuid4(), definition_id=definition_id, name="run", status=status, fingerprint=fingerprint, config_snapshot={},
                policy_versions=[{"name": policy[0], "version": policy[1]}], queued_at=NOW - timedelta(days=age_days, minutes=1),
                finished_at=NOW - timedelta(days=age_days), summary=summary)
    db.add(r)
    db.flush()
    for host, ip, state, extra in endpoints:
        db.add(RunEndpoint(run_id=r.id, endpoint_id=f"{ip}:443/tcp", hostname=host, ip_address=ip, port="443", compliance_status=state, **extra))
    for fid, severity, affected in findings:
        db.add(RunFinding(run_id=r.id, finding_id=fid, title=fid, category="c", severity=severity, status="KO", affected_endpoint_ids=[f"{ip}:443/tcp" for ip in affected]))
    db.flush()
    return r


def finished(db):
    from sqlalchemy import select
    return list(db.execute(select(ScanRun).where(ScanRun.status.in_(("completed", "partial"))).order_by(ScanRun.finished_at.desc())).scalars())


def test_no_data_gives_no_rate_and_no_invented_values(db):
    p = dashboard.posture(db, [])
    assert p["endpoints"] == {"total": 0, "compliant": 0, "non_compliant": 0, "unevaluated": 0, "rate": None}
    assert p["certificates"]["items"] == [] and p["vigilance"] == []
    assert dashboard.trend(db, [], None)["points"] == []


def test_rate_counts_only_evaluated_endpoints_and_reports_the_others(db):
    d = definition(db)
    run(db, d, endpoints=[("a", "10.0.0.1", "compliant", {}), ("b", "10.0.0.2", "compliant", {}), ("c", "10.0.0.3", "non_compliant", {}),
                          ("d", "10.0.0.4", "error", {}), ("e", "10.0.0.5", "not_tested", {})], status="partial")
    e = dashboard.posture(db, finished(db))["endpoints"]
    assert (e["total"], e["compliant"], e["non_compliant"], e["unevaluated"], e["rate"]) == (5, 2, 1, 2, 66.7)


def test_only_unevaluated_endpoints_give_no_rate_not_zero(db):
    run(db, definition(db), endpoints=[("a", "10.0.0.1", "error", {})], status="partial")
    assert dashboard.posture(db, finished(db))["endpoints"]["rate"] is None


def test_an_endpoint_scanned_by_several_runs_or_definitions_counts_once_from_the_latest(db):
    d1, d2 = definition(db), definition(db)
    run(db, d1, age_days=3, endpoints=[("a", "10.0.0.1", "non_compliant", {})])
    run(db, d1, age_days=1, endpoints=[("a", "10.0.0.1", "compliant", {})])  # latest of d1 supersedes the older run
    run(db, d2, age_days=2, endpoints=[("a", "10.0.0.1", "non_compliant", {})])
    run(db, definition(db), age_days=2, endpoints=[("a-other-name", "10.0.0.1", "compliant", {})])
    e = dashboard.posture(db, finished(db))["endpoints"]
    assert e["total"] == 2  # same IP behind a different name stays distinct
    assert (e["compliant"], e["non_compliant"]) == (2, 0)  # the newest basis run wins for the shared endpoint (d1, compliant)


def test_failed_runs_are_ignored_by_the_picture(db):
    d = definition(db)
    run(db, d, age_days=2, endpoints=[("a", "10.0.0.1", "compliant", {})])
    run(db, d, age_days=1, status="failed", endpoints=[("a", "10.0.0.1", "non_compliant", {})])
    assert dashboard.posture(db, finished(db))["endpoints"]["compliant"] == 1


def test_findings_are_unique_and_counted_by_distinct_endpoints_and_exclude_scan_errors_and_informational(db):
    d = definition(db)
    run(db, d, endpoints=[("a", "10.0.0.1", "non_compliant", {}), ("b", "10.0.0.2", "non_compliant", {}), ("c", "10.0.0.3", "compliant", {})],
        findings=[("TLS_DEPRECATED_VERSION", "high", ["10.0.0.1", "10.0.0.2"]), ("CERTIFICATE_REVOKED", "high", ["10.0.0.1"]),
                  ("SCAN_ERROR", "low", ["10.0.0.3"]), ("PQC", "informational", ["10.0.0.3"]), ("OLD", "high", ["192.0.2.9"])])
    p = dashboard.posture(db, finished(db))
    assert p["findings"]["high"] == {"unique": 2, "endpoints": 2}  # OLD concerns an endpoint outside the basis
    assert p["findings"]["occurrences"] == 3 and p["findings"]["critical"] == {"unique": 0, "endpoints": 0}
    assert [(v["finding_id"], v["endpoints"]) for v in p["vigilance"]] == [("TLS_DEPRECATED_VERSION", 2), ("CERTIFICATE_REVOKED", 1)]


def test_only_failed_complementary_checks_are_reported(db):
    checks = [{"check_id": "ecdhe_groups", "status": "FAIL"}, {"check_id": "client_auth", "status": "PASS"}, {"check_id": "early_data", "status": "INCONCLUSIVE"},
              {"check_id": "tls_compression", "status": "NOT_TESTED"}]
    run(db, definition(db), endpoints=[("a", "10.0.0.1", "compliant", {"tls_checks": checks})])
    vigilance = dashboard.posture(db, finished(db))["vigilance"]
    assert [v["finding_id"] for v in vigilance] == ["ecdhe_groups"] and vigilance[0]["severity"] is None


def test_certificates_are_deduplicated_by_fingerprint_and_aged_since_the_scan(db):
    cert = lambda days, fp: {"certificate": {"remaining_days": days, "fingerprint": fp, "subject": f"CN={fp}", "valid_until": "x"}}  # noqa: E731
    run(db, definition(db), age_days=2, endpoints=[("a", "10.0.0.1", "compliant", cert(10, "A")), ("b", "10.0.0.2", "compliant", cert(10, "A")),
                                                  ("c", "10.0.0.3", "compliant", cert(1, "B")), ("d", "10.0.0.4", "compliant", cert(200, "C")),
                                                  ("e", "10.0.0.5", "compliant", {})])
    c = dashboard.posture(db, finished(db))["certificates"]
    assert (c["expired"], c["expiring"]) == (1, 1)  # B: 1 - 2 days elapsed -> expired; A: 10 - 2 = 8 days; C is far away; e has no data
    assert [(i["remaining_days"], i["endpoints"]) for i in c["items"]] == [(-1, 1), (8, 2)]


def test_policies_are_listed_and_a_mix_is_flagged(db):
    d1, d2 = definition(db), definition(db)
    run(db, d1, policy=("P", 1), endpoints=[("a", "10.0.0.1", "compliant", {})])
    assert dashboard.posture(db, finished(db))["mixed_policies"] is False
    run(db, d2, policy=("P", 2), endpoints=[("b", "10.0.0.2", "compliant", {})])
    p = dashboard.posture(db, finished(db))
    assert p["mixed_policies"] is True and p["policies"] == [{"name": "P", "version": 1}, {"name": "P", "version": 2}]


def test_trend_follows_one_definition_and_flags_incomparable_points(db):
    d, other = definition(db, "A"), definition(db, "B")
    def summary(c, n, total=None):
        return {"compliant_endpoints": c, "non_compliant_endpoints": n, "total_endpoints": total or c + n}
    run(db, d, age_days=3, summary=summary(1, 3))
    run(db, d, age_days=2, summary=summary(2, 2))
    run(db, d, age_days=1, fingerprint="other-profile", summary=summary(4, 0, total=6))
    run(db, other, age_days=0, summary=summary(0, 0, total=3), status="partial")
    t = dashboard.trend(db, finished(db), d)
    assert [p["rate"] for p in t["points"]] == [25.0, 50.0, 100.0]
    assert [p["comparable"] for p in t["points"]] == [True, True, False]
    assert (t["points"][2]["evaluated"], t["points"][2]["total"]) == (4, 6)
    assert {x["name"] for x in t["definitions"]} == {"A", "B"}
    only_other = dashboard.trend(db, finished(db), other)
    assert only_other["points"][0]["rate"] is None  # nothing evaluated: no rate, not 0
    assert dashboard.trend(db, finished(db), uuid.uuid4())["definition_id"] == str(other)  # unknown id: falls back to the latest definition
