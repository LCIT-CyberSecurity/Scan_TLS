"""Post-deployment smoke test, run inside the api container:  docker compose exec -T api python - < tests/smoke/smoke.py

Environment: SMOKE_ADMIN_PASSWORD (initial one-time password), SMOKE_TARGET, SMOKE_PORTS.
Scans ONLY the target you give (use your own lab / the deployment itself), never third-party hosts.
"""
import os
import sys
import time

import httpx

base = "http://localhost:8000"
target, ports = os.environ["SMOKE_TARGET"], os.environ.get("SMOKE_PORTS", "443")
c = httpx.Client(base_url=base, timeout=30)


def call(method, path, **kw):
    r = c.request(method, path, headers={"x-csrf-token": csrf}, **kw)
    assert r.status_code < 300, (method, path, r.status_code, r.text)
    return r.json() if r.content else None


r = c.post("/api/auth/login", json={"username": "admin", "password": os.environ["SMOKE_ADMIN_PASSWORD"]})
assert r.status_code == 200, r.text
csrf = r.json()["csrf_token"]
# the session cookie is Secure (production); talking plain HTTP inside the container, pass it explicitly
c.headers["Cookie"] = r.headers["set-cookie"].split(";")[0]
if r.json()["user"]["must_change_password"]:
    new = "Smoke-Test-Pass-" + str(int(time.time()))
    call("POST", "/api/auth/password", json={"current_password": os.environ["SMOKE_ADMIN_PASSWORD"], "new_password": new})
    print("password changed (must_change_password enforced)")
policy = call("POST", "/api/policies", json={"name": f"smoke-{int(time.time())}", "content": {
    "allowed_versions": ["TLSv1.2", "TLSv1.3"], "allowed_cipher_algorithms": ["AES-GCM", "CHACHA20-POLY1305"],
    "allowed_signature_hashes": ["SHA-256", "SHA-384", "SHA-512"], "minimum_rsa_bits": 2048}})
call("POST", f"/api/policies/{policy['id']}/publish")
profile = call("POST", "/api/profiles", json={"name": f"smoke-{int(time.time())}", "content": {"scan": {"ports": ports, "crypto": "standard", "workers": 2}, "checks": {"certificate": {"revocation": {"enabled": False}}}}})
call("POST", f"/api/profiles/{profile['id']}/publish")
t = call("POST", "/api/targets", json={"value": target})
d = call("POST", "/api/scan-definitions", json={"name": "smoke", "target_ids": [t["id"]], "policy_ids": [policy["id"]], "profile_id": profile["id"]})
run = call("POST", f"/api/scan-definitions/{d['id']}/run")
for _ in range(120):
    detail = call("GET", f"/api/scan-runs/{run['run_id']}")
    if detail["status"] not in ("queued", "running"):
        break
    time.sleep(2)
print("status:", detail["status"], "endpoints:", len(detail["endpoints"]), "findings:", len(detail["findings"]), "error:", detail["error"])
assert detail["status"] in ("completed", "partial") and detail["endpoints"], detail["error"]
html = c.get(f"/api/scan-runs/{run['run_id']}/reports/html")
assert html.status_code == 200 and b"<html" in html.content.lower()
print("report html bytes:", len(html.content))
print("SMOKE OK")
