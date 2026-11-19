from __future__ import annotations

import asyncio
import threading

from orion_app.services import mail_security as checks


def run(coro):
    return asyncio.run(coro)


def fake_dns(monkeypatch, records: dict[tuple[str, str], list[str]]):
    async def query(self, name, rdtype):
        return records.get((name.lower(), rdtype.upper()), [])

    monkeypatch.setattr(checks._Lookup, "query", query)
    monkeypatch.setattr(checks, "_txt", lambda answer: answer or [])


def test_spf_version_marker_alone_is_not_full_compliance(monkeypatch):
    fake_dns(monkeypatch, {("example.org", "TXT"): ["v=spf1"]})
    result = run(checks._spf("example.org", checks._Lookup()))
    assert result["status"] == "warning", result
    assert "does not establish" in result["message"]


def test_spf_lookup_budget_over_ten_is_non_compliant(monkeypatch):
    mechanisms = " ".join(f"a:mx{i}.example.org" for i in range(11))
    fake_dns(monkeypatch, {("example.org", "TXT"): [f"v=spf1 {mechanisms} -all"]})
    result = run(checks._spf("example.org", checks._Lookup()))
    assert result["status"] == "non_compliant"
    assert "10-DNS-lookup" in result["message"]


def test_spf_negative_all_is_recognized_and_duplicate_all_is_rejected(monkeypatch):
    fake_dns(monkeypatch, {("example.org", "TXT"): ["v=spf1 ip4:192.0.2.1 -all"]})
    result = run(checks._spf("example.org", checks._Lookup()))
    assert result["status"] == "compliant", result
    fake_dns(monkeypatch, {("example.org", "TXT"): ["v=spf1 -all +all"]})
    result = run(checks._spf("example.org", checks._Lookup()))
    assert result["status"] == "non_compliant", result


def test_dmarc_p_none_is_warning_and_reports_are_not_assumed(monkeypatch):
    fake_dns(monkeypatch, {("_dmarc.example.org", "TXT"): ["v=DMARC1; p=none; rua=mailto:dmarc@example.org; pct=50"]})
    result = run(checks._dmarc("example.org", checks._Lookup()))
    assert result["status"] == "warning", result
    assert result["details"]["p"] == "none"
    assert "does not prove" in result["message"]


def test_dmarc_invalid_policy_is_non_compliant(monkeypatch):
    fake_dns(monkeypatch, {("_dmarc.example.org", "TXT"): ["v=DMARC1; p=discard"]})
    result = run(checks._dmarc("example.org", checks._Lookup()))
    assert result["status"] == "non_compliant"


def test_dkim_without_known_selector_is_explicitly_not_evaluated(monkeypatch):
    results = run(checks._dkim("example.org", [], checks._Lookup()))
    assert len(results) == 1
    assert results[0]["status"] == "not_evaluated"


def test_tls_rpt_requires_destination(monkeypatch):
    fake_dns(monkeypatch, {("_smtp._tls.example.org", "TXT"): ["v=TLSRPTv1"]})
    result = run(checks._tls_rpt("example.org", checks._Lookup()))
    assert result["status"] == "non_compliant"


def test_tls_rpt_validates_destinations_and_requires_version_first(monkeypatch):
    fake_dns(monkeypatch, {("_smtp._tls.example.org", "TXT"): ["rua=mailto:reports@example.org; v=TLSRPTv1"]})
    assert run(checks._tls_rpt("example.org", checks._Lookup()))["status"] == "non_compliant"
    fake_dns(monkeypatch, {("_smtp._tls.example.org", "TXT"): ["v=TLSRPTv1; rua=https://reports.example.org/ingest"]})
    assert run(checks._tls_rpt("example.org", checks._Lookup()))["status"] == "compliant"
    fake_dns(monkeypatch, {("_smtp._tls.example.org", "TXT"): ["v=TLSRPTv1; rua=https:///missing-host"]})
    assert run(checks._tls_rpt("example.org", checks._Lookup()))["status"] == "non_compliant"


def test_mta_sts_blocks_private_and_loopback_addresses(monkeypatch):
    monkeypatch.setattr(checks.socket, "getaddrinfo", lambda *args, **kwargs: [
        (checks.socket.AF_INET, checks.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
    ])
    try:
        checks._resolve_public("mta-sts.example.org")
    except ValueError as error:
        assert "non-public" in str(error)
    else:
        raise AssertionError("loopback MTA-STS address must be blocked")


def test_mta_sts_rejects_malformed_policy_and_reports_fetch_failures(monkeypatch):
    fake_dns(monkeypatch, {("_mta-sts.example.org", "TXT"): ["v=STSv1; id=policy-1"]})
    monkeypatch.setattr(checks, "_fetch_mta_sts", lambda _host: (200, "not a policy"))
    malformed = run(checks._mta_sts("example.org", checks._Lookup(), []))
    assert malformed["status"] == "non_compliant"

    def unavailable(_host):
        raise TimeoutError("bounded test timeout")

    monkeypatch.setattr(checks, "_fetch_mta_sts", unavailable)
    unavailable_result = run(checks._mta_sts("example.org", checks._Lookup(), []))
    assert unavailable_result["status"] == "error"


def test_mta_sts_does_not_follow_redirects(monkeypatch):
    class FakeSocket:
        sent = False
        def sendall(self, _request):
            self.sent = True
        def settimeout(self, _timeout):
            pass
        def recv(self, _limit):
            if self.sent:
                self.sent = False
                return b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\nContent-Length: 0\r\n\r\n"
            return b""
        def close(self):
            pass

    class FakeContext:
        def wrap_socket(self, _sock, server_hostname):
            assert server_hostname == "mta-sts.example.org"
            return FakeSocket()

    monkeypatch.setattr(checks, "_resolve_public", lambda _host: ["93.184.216.34"])
    monkeypatch.setattr(checks.socket, "create_connection", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(checks.ssl, "create_default_context", FakeContext)
    try:
        checks._fetch_mta_sts("mta-sts.example.org")
    except ValueError as error:
        assert "redirect was blocked" in str(error)
    else:
        raise AssertionError("MTA-STS redirect must be blocked")


def test_dane_without_mx_is_not_evaluated():
    result = run(checks._dane("example.org", checks._Lookup(), []))
    assert result["status"] == "not_evaluated"


def test_existing_smtp_observations_are_linked_without_new_probes():
    domains = [{"domain": "example.org", "mx": ["mail.example.org"], "checks": []}]
    checks.attach_smtp_observations(domains, [
        {"hostname": "mail.example.org", "port": "25", "supported_tls_versions": ["TLSv1.3"]},
        {"hostname": "other.example.org", "port": "587", "supported_tls_versions": ["TLSv1.2"]},
    ])
    assert domains[0]["smtp_starttls"][0]["status"] == "observed"
    assert domains[0]["smtp_starttls"][0]["tls_versions"] == ["TLSv1.3"]
    checks.attach_smtp_observations(domains, [])
    assert domains[0]["smtp_starttls"][0]["status"] == "not_tested"


def test_cancelled_scan_marks_remaining_mail_checks_not_evaluated():
    cancelled = threading.Event()
    cancelled.set()
    result = run(checks.inspect_domain("example.org", {"checks": {"spf": True, "dmarc": True}}, cancelled))
    assert [row["status"] for row in result["checks"]] == ["not_evaluated", "not_evaluated"]
