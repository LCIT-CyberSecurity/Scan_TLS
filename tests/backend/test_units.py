"""Pure unit tests (no running stack needed): scheduling maths, planner, fingerprint, scrubbing, parsing."""
from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from tls_scan_app.services.logs import ScrubFilter, scrub_text
from tls_scan_app.services.planner import PlanError, fingerprint, job_from_snapshot, validate_policy_content, validate_profile_content
from tls_scan_app.services.schedule_calc import ScheduleError, next_after, validate
from tls_scan_app.services.targets import TargetError, normalize_ports, normalize_target
from tls_scan_app.auth.passwords import hash_password, is_acceptable_for_production, verify_password
from tls_scan_app.auth import flow_cookie
from tls_scan_app.models.user import Role, role_at_least

PARIS = "Europe/Paris"


def utc(*a):
    return datetime(*a, tzinfo=UTC)


class TestSchedules:
    def test_daily_fires_once_per_local_day_across_spring_forward(self):
        # Paris springs forward on 2026-03-29 (02:00 -> 03:00): 02:30 does not exist that day.
        t, seen = utc(2026, 3, 27, 12), []
        for _ in range(5):
            t = next_after("daily", {"time": "02:30"}, PARIS, t)
            seen.append(t.astimezone(ZoneInfo(PARIS)))
        days = [s.date().isoformat() for s in seen]
        assert days == ["2026-03-28", "2026-03-29", "2026-03-30", "2026-03-31", "2026-04-01"]
        assert seen[0].hour == 2 and seen[2].hour == 2  # wall-clock preserved outside the gap

    def test_daily_once_in_autumn_fold(self):
        t = utc(2026, 10, 24, 12)
        a = next_after("daily", {"time": "02:30"}, PARIS, t)
        b = next_after("daily", {"time": "02:30"}, PARIS, a)
        assert b - a in (timedelta(hours=24), timedelta(hours=25))
        assert b.astimezone(ZoneInfo(PARIS)).date().isoformat() == "2026-10-26"  # the fold day is not fired twice

    def test_weekly_and_monthly(self):
        mon = next_after("weekly", {"time": "08:00", "weekday": 0}, "UTC", utc(2026, 10, 10, 12))  # Saturday
        assert mon == utc(2026, 10, 12, 8)
        assert next_after("monthly", {"time": "08:00", "day": 5}, "UTC", utc(2026, 10, 10, 12)) == utc(2026, 11, 5, 8)
        assert next_after("monthly", {"time": "08:00", "day": 5}, "UTC", utc(2026, 12, 10, 12)) == utc(2027, 1, 5, 8)

    def test_once_exhausts(self):
        assert next_after("once", {"at": "2026-10-10T12:00:00+00:00"}, "UTC", utc(2026, 10, 10, 13)) is None
        assert next_after("once", {"at": "2026-10-10T12:00:00+00:00"}, "UTC", utc(2026, 10, 10, 11)) == utc(2026, 10, 10, 12)

    def test_cron(self):
        assert next_after("cron", {"expr": "0 3 * * 1"}, "UTC", utc(2026, 10, 10)) == utc(2026, 10, 12, 3)

    @pytest.mark.parametrize("kind,params", [("cron", {"expr": "*/1 * * * *"}), ("cron", {"expr": "bad"}), ("daily", {"time": "24:00"}), ("weekly", {"time": "01:00", "weekday": 7}), ("monthly", {"time": "01:00", "day": 0}), ("nope", {})])
    def test_invalid(self, kind, params):
        with pytest.raises(ScheduleError):
            validate(kind, params, "UTC")


class TestTargets:
    @pytest.mark.parametrize("raw,expected", [("Example.ORG.", ("example.org", "fqdn")), ("10.0.0.1", ("10.0.0.1", "ip")), ("10.0.0.5/24", ("10.0.0.0/24", "cidr")), ("2001:db8::1", ("2001:db8::1", "ip"))])
    def test_valid(self, raw, expected):
        assert normalize_target(raw) == expected

    @pytest.mark.parametrize("raw", ["", " ", "-oN x", "a b", "a;b", "a|b", "$(id)", "a`b`", "http://x", "a/b/c", "x" * 300 + ".org", "--script=x", "a\nb"])
    def test_invalid(self, raw):
        with pytest.raises(TargetError):
            normalize_target(raw)

    def test_ports(self):
        assert normalize_ports("443, 8443,9000-9010") == "443,8443,9000-9010"
        for bad in ("0", "70000", "9000-8000", "a", "443;"):
            with pytest.raises(TargetError):
                normalize_ports(bad)


POLICY = {"allowed_versions": ["TLSv1.2"], "allowed_cipher_algorithms": ["AES-GCM"], "allowed_signature_hashes": ["SHA-256"], "minimum_rsa_bits": 2048}


class TestPlanner:
    def test_policy_validation(self):
        validate_policy_content(POLICY)
        for bad in ({**POLICY, "minimum_rsa_bits": True}, {**POLICY, "allowed_versions": []}, {**POLICY, "extra": 1}):
            with pytest.raises(PlanError):
                validate_policy_content(bad)

    def test_profile_validation_uses_the_engine_parser(self):
        validate_profile_content({"scan": {"ports": "443", "crypto": "standard"}, "checks": {}})
        with pytest.raises(PlanError):
            validate_profile_content({"scan": {"crypto": "quantum-magic"}})
        with pytest.raises(PlanError):  # unsupported parameters are refused, not silently ignored
            validate_profile_content({"scan": {}, "bogus": {}})
        with pytest.raises(PlanError):  # custom trust stores read server paths: not in V1
            validate_profile_content({"checks": {"certificate": {"trust": {"custom_stores": [{"name": "x", "type": "pem", "path": "/etc/passwd"}]}}}})

    def snapshot(self, **over):
        snap = {"definition": {"id": "d", "name": "My scan!"}, "profile": {"id": "p", "version_id": "pv", "version": 1},
                "scan": {"ports": "443", "crypto": "standard", "workers": 3}, "checks": {}, "passes": [{"ports": "443", "targets": ["a.example.org", "10.0.0.0/30"]}],
                "policy_mode": "strict_all", "policies": [{"policy_id": "x", "version_id": "v1", "name": "p1", "version": 2, "content": POLICY}], "export_formats": ["csv", "html"]}
        snap.update(over)
        return snap

    def test_job_from_snapshot_matches_the_engine_model(self):
        job, passes = job_from_snapshot(self.snapshot(), str(uuid.uuid4()), "/tmp/out", None, max_workers=2)
        assert job.workers == 2  # capped by the installation limit
        assert job.policies[0].name == "p1" and job.policies[0].version == "2" and job.policies[0].minimum_rsa_bits == 2048
        assert job.policy_mode == "strict_all" and set(job.export_formats) == {"csv", "html"}
        assert passes == [("a.example.org,10.0.0.0/30", "443")]
        assert job.report_name == "My_scan"  # safe file name (punctuation replaced, edges trimmed)

    def test_fingerprint_ignores_outputs_and_worker_count_but_not_observations(self):
        base = fingerprint(self.snapshot())
        assert fingerprint(self.snapshot(export_formats=["md"])) == base
        assert fingerprint(self.snapshot(scan={"ports": "443", "crypto": "standard", "workers": 8})) == base
        assert fingerprint(self.snapshot(scan={"ports": "8443", "crypto": "standard", "workers": 3})) != base
        other = self.snapshot()
        other["policies"][0]["version_id"] = "v2"  # a new policy version is a different scan
        assert fingerprint(other) != base
        other = self.snapshot(passes=[{"ports": "443", "targets": ["b.example.org"]}])
        assert fingerprint(other) != base


class TestSecurityHelpers:
    def test_scrub(self):
        assert "hunter2" not in scrub_text("login password=hunter2 ok")
        assert "s3cr3t" not in scrub_text("Authorization: s3cr3t")
        assert "pw" not in scrub_text("postgresql://user:pw@db/x")
        assert scrub_text("nothing to hide") == "nothing to hide"

    def test_log_filter_scrubs_records(self):
        rec = logging.LogRecord("x", logging.INFO, "f", 1, "token=%s", ("abc123",), None)
        ScrubFilter().filter(rec)
        assert "abc123" not in rec.getMessage()

    def test_password_hashing_and_policy(self):
        h = hash_password("Correct-Horse-Battery-9!")
        assert verify_password("Correct-Horse-Battery-9!", h) and not verify_password("wrong", h) and not verify_password("x", None)
        assert is_acceptable_for_production("short") and is_acceptable_for_production("password1234") and is_acceptable_for_production("aaaaaaaaaaaaaa")
        assert is_acceptable_for_production("Correct-Horse-Battery-9!") is None

    def test_flow_cookie_is_tamper_evident_and_expires(self, monkeypatch):
        value = flow_cookie.sign({"state": "s"}, "secret")
        assert flow_cookie.verify(value, "secret")["state"] == "s"
        assert flow_cookie.verify(value, "other") is None
        assert flow_cookie.verify(value[:-1] + ("0" if value[-1] != "0" else "1"), "secret") is None
        monkeypatch.setattr("time.time", lambda: datetime.now().timestamp() + 1000)
        assert flow_cookie.verify(value, "secret") is None

    def test_role_hierarchy(self):
        assert role_at_least(Role.ADMIN, Role.OPERATOR) and role_at_least(Role.USER, Role.AUDITOR)
        assert not role_at_least(Role.AUDITOR, Role.USER) and not role_at_least(Role.OPERATOR, Role.ADMIN)


def test_rate_limiter_counts_without_consuming():
    from tls_scan_app.services.rate_limit import SlidingWindowLimiter

    lim = SlidingWindowLimiter()
    assert lim.count("k", 60) == 0 and lim.count("k", 60) == 0  # reading does not record
    for _ in range(3):
        lim.hit("k")
    assert lim.count("k", 60) == 3
