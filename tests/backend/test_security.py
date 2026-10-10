"""HTTP-level security checks against the running stack."""
from __future__ import annotations

import httpx
import pytest

from conftest import API, LAB, make_definition, wait_final


def test_security_headers_on_api_responses():
    r = httpx.get(f"{API}/api/health/live")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store" and "x-request-id" in r.headers


def test_session_cookie_flags():
    from conftest import ADMIN_PASSWORD, ADMIN_USER

    r = httpx.post(f"{API}/api/auth/login", json={"username": "nobody@example.com", "password": "x" * 14})
    assert r.status_code == 401 and "set-cookie" not in r.headers
    # a successful login sets an HttpOnly, SameSite cookie (Secure is off only in this plain-HTTP test stack)
    from conftest import STRONG

    for pw in (STRONG, ADMIN_PASSWORD):
        ok = httpx.post(f"{API}/api/auth/login", json={"username": ADMIN_USER, "password": pw})
        if ok.status_code == 200:
            cookie = ok.headers["set-cookie"].lower()
            assert "httponly" in cookie and "samesite=lax" in cookie
            assert ok.json()["csrf_token"] and "password" not in ok.text.lower().replace("must_change_password", "")
            break
    else:
        pytest.fail("admin could not sign in")


def test_logout_revokes_the_session(user):
    from conftest import Api, STRONG

    api = Api()
    api.login(user.user["email"], STRONG)
    assert api.get("/api/targets").status_code == 200
    stolen = httpx.Client(base_url=API, cookies=api.http.cookies, headers={"x-csrf-token": api.csrf})
    assert api.post("/api/auth/logout").status_code == 200
    assert stolen.get("/api/targets").status_code == 401  # the old token is dead server-side


def test_report_download_requires_auth_and_is_not_traversable(user, auditor, catalog):
    run = make_definition(user, catalog, [LAB], name="sec-report", ports="443")
    final = wait_final(user, user.post(f"/api/scan-definitions/{run['id']}/run").json()["run_id"])
    assert httpx.get(f"{API}/api/scan-runs/{final['id']}/reports/html").status_code == 401
    for fmt in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd", "exe", "metadata/../../x"):
        assert auditor.get(f"/api/scan-runs/{final['id']}/reports/{fmt}").status_code in (404, 405)
    r = auditor.get(f"/api/scan-runs/{final['id']}/reports/html")
    assert r.status_code == 200 and "sandbox" in r.headers["content-security-policy"] and r.headers["x-content-type-options"] == "nosniff"


def test_diagnostics_do_not_leak_secrets(admin):
    import os

    body = str(admin.get("/api/admin/diagnostics").json()) + str(admin.get("/api/admin/settings").json())
    for secret in (os.environ["TLS_SCAN_SESSION_SECRET"] if "TLS_SCAN_SESSION_SECRET" in os.environ else "crashtest-only-session-secret", os.environ["TLS_SCAN_LOCAL_ADMIN_PASSWORD"], os.environ["TLS_SCAN_DATABASE_URL"]):
        assert secret not in body


def test_sql_injection_attempts_are_inert(user):
    r = user.get("/api/targets", params={"q": "'; DROP TABLE targets; --"})
    assert r.status_code == 200 and r.json() == []
    assert user.get("/api/targets").status_code == 200  # table still there
    assert user.post("/api/targets", json={"value": "x.example.org", "description": "'; DROP TABLE users; --", "tags": ["a'b\"c"]}).status_code in (201, 409)


def test_engine_subprocess_has_no_secrets_in_environment():
    """The scan subprocess is started with an allow-listed environment (see workers/worker.py)."""
    import inspect

    from tls_scan_app.workers import worker

    src = inspect.getsource(worker.run_subprocess)
    assert 'k in ("PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH", "SSL_CERT_FILE")' in src


def test_login_rate_limit_unit():
    from tls_scan_app.services.rate_limit import SlidingWindowLimiter

    lim = SlidingWindowLimiter()
    assert [lim.allow("k", 3, 60) for _ in range(5)] == [True, True, True, False, False]
    lim.reset("k")
    assert lim.allow("k", 3, 60)
