"""CrashTest dataset: demo accounts, SI, tags, targets (lab TLS scenarios), policies, profiles, definitions.

Run inside the api container:  docker compose exec -T api python - < seed.py
Refuses to run unless the application reports crashtest mode, so demo passwords can never reach a real install.
"""
import os
import sys

import httpx

DEMO_PASSWORD = "CrashTest-Demo-2026!"  # demo only, never used outside the CrashTest stack
ADMIN_INITIAL = os.environ.get("TLS_SCAN_LOCAL_ADMIN_PASSWORD", "")
ADMIN_FINAL = "CrashTest-Admin-2026!"
LAB = "lab-tls"

base = httpx.Client(base_url="http://localhost:8000", timeout=60)
if not base.get("/api/auth/providers").json().get("crashtest"):
    sys.exit("Refusing to seed: this is not a CrashTest installation (TLS_SCAN_CRASHTEST is not true).")


class Session:
    def __init__(self, user, password):
        self.c = httpx.Client(base_url="http://localhost:8000", timeout=60)
        r = self.c.post("/api/auth/login", json={"username": user, "password": password})
        assert r.status_code == 200, (user, r.text)
        self.csrf = r.json()["csrf_token"]
        self.c.headers["Cookie"] = r.headers["set-cookie"].split(";")[0]  # Secure cookie over plain HTTP inside the container
        self.user = r.json()["user"]

    def call(self, method, path, ok=(200, 201, 202, 204, 409), **kw):
        r = self.c.request(method, path, headers={"x-csrf-token": self.csrf}, **kw)
        assert r.status_code in ok, (method, path, r.status_code, r.text)
        return r.json() if r.content else None


def login_admin():
    for pw in (ADMIN_FINAL, ADMIN_INITIAL):
        r = httpx.post("http://localhost:8000/api/auth/login", json={"username": "admin", "password": pw})
        if r.status_code == 200:
            s = Session("admin", pw)
            if s.user["must_change_password"]:
                s.call("POST", "/api/auth/password", json={"current_password": pw, "new_password": ADMIN_FINAL})
                s = Session("admin", ADMIN_FINAL)
            return s
    sys.exit("cannot sign in as admin")


admin = login_admin()
existing = {u["email"]: u for u in admin.call("GET", "/api/admin/users")}
for name, role in (("operator", "OPERATOR"), ("user", "USER"), ("user2", "USER"), ("auditor", "AUDITOR")):
    email = f"{name}@crashtest.example.com"
    if email in existing:
        continue
    temp = admin.call("POST", "/api/admin/users", json={"email": email, "display_name": name.title(), "role": role})["temporary_password"]
    s = Session(email, temp)
    s.call("POST", "/api/auth/password", json={"current_password": temp, "new_password": DEMO_PASSWORD})

op = Session("operator@crashtest.example.com", DEMO_PASSWORD)
user = Session("user@crashtest.example.com", DEMO_PASSWORD)

# policies and profiles
def versioned(kind, name, content):
    items = op.call("GET", f"/api/{kind}")
    found = next((i for i in items if i["name"] == name), None)
    if found:
        return found["id"]
    item = op.call("POST", f"/api/{kind}", json={"name": name, "content": content})
    op.call("POST", f"/api/{kind}/{item['id']}/publish")
    return item["id"]


anssi = versioned("policies", "ANSSI (strict)", {"allowed_versions": ["TLSv1.2", "TLSv1.3"], "allowed_cipher_algorithms": ["AES-GCM", "AES-CCM", "CHACHA20-POLY1305"],
                                                "allowed_signature_hashes": ["SHA-256", "SHA-384", "SHA-512"], "minimum_rsa_bits": 2048})
lenient = versioned("policies", "Internal (lenient)", {"allowed_versions": ["TLSv1.2", "TLSv1.3"], "allowed_cipher_algorithms": ["AES-GCM", "AES-CBC", "CHACHA20-POLY1305"],
                                                      "allowed_signature_hashes": ["SHA-256", "SHA-384", "SHA-512", "SHA-1"], "minimum_rsa_bits": 2048})
lab_profile = versioned("profiles", "Lab - all scenarios", {"scan": {"ports": "443,8443,8444,8445,8446,80", "crypto": "standard", "workers": 3},
                                                            "checks": {"certificate": {"enabled": True, "expires_within_days": 30, "revocation": {"enabled": False}}}})
quick_profile = versioned("profiles", "Lab - HTTPS only", {"scan": {"ports": "443", "crypto": "standard", "workers": 2}, "checks": {"certificate": {"revocation": {"enabled": False}}}})

# classification
si = {}
for name, parent in (("Production", None), ("Internal", None), ("Hosting", None), ("Web", "Production"), ("Messaging", "Production"), ("Infrastructure", "Internal")):
    body = {"name": name, "parent_id": si[parent] if parent else None}
    r = user.call("POST", "/api/information-systems", json=body)
    if r and "id" in r:
        si[name] = r["id"]
if len(si) < 6:
    si = {s["name"]: s["id"] for s in user.call("GET", "/api/information-systems")}

# targets (the lab host is the only thing ever scanned by the CrashTest)
specs = [("443", ["Production", "Internet"], "Web"), ("8443", ["Production", "Critical"], "Web"), ("8444", ["Internal"], "Infrastructure"),
         ("8445", ["Internal", "DMZ"], "Messaging"), ("80", ["Recette"], "Web")]
tids = []
for port, tags, sub in specs:
    r = user.call("POST", "/api/targets", json={"value": LAB, "ports": port, "description": f"Lab scenario port {port}", "tags": tags, "si_ids": [si[sub]]})
    if r and "id" in r:
        tids.append(r["id"])
tids = [t["id"] for t in user.call("GET", "/api/targets", params={"q": LAB})]
group = user.call("POST", "/api/target-groups", json={"name": "Lab - all", "target_ids": tids, "tags": ["Lab"]})
if not (group and "id" in group):  # re-run: the group already exists
    group = next(g for g in user.call("GET", "/api/target-groups") if g["name"] == "Lab - all")

# definitions
def definition(name, profile, policies, target_ids, group_ids=()):
    existing = next((d for d in user.call("GET", "/api/scan-definitions") if d["name"] == name), None)
    if existing:
        return existing
    r = user.call("POST", "/api/scan-definitions", json={"name": name, "profile_id": profile, "policy_ids": policies, "target_ids": list(target_ids),
                                                         "group_ids": list(group_ids), "tags": ["Lab"], "si_ids": [si["Production"]]})
    return r if r and "id" in r else next(d for d in user.call("GET", "/api/scan-definitions") if d["name"] == name)


d_all = definition("Lab - full scenario scan (ANSSI)", lab_profile, [anssi], [], [group["id"]])
d_https = definition("Lab - HTTPS only", quick_profile, [anssi, lenient], [tids[0]])
if not user.call("GET", "/api/schedules"):
    user.call("POST", "/api/schedules", json={"definition_id": d_https["id"], "kind": "daily", "params": {"time": "03:00"}, "timezone": "Europe/Paris"})
admin.call("PUT", "/api/admin/settings/notifications", json={"value": {"connector": "smtp", "smtp": {"host": "smtp-sink", "port": 1025, "starttls": False, "from": "tls-scan@crashtest.example.com"}}})
print("CrashTest seeded: users operator/user/user2/auditor@crashtest.example.com (demo password in seed.py); admin password:", ADMIN_FINAL)
