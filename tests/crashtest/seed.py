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
for name, parent in (("Production", None), ("Internal", None), ("Hosting", None), ("Web", "Production"), ("Messaging", "Production"),
                    ("Infrastructure", "Internal"), ("Cloud Services", None), ("Partner Network", None)):
    body = {"name": name, "parent_id": si[parent] if parent else None}
    r = user.call("POST", "/api/information-systems", json=body)
    if r and "id" in r:
        si[name] = r["id"]
if len(si) < 8:
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

# Network-map fixtures are confined to the CrashTest database and use documentation-only addresses.
targets_by_port = {target["ports"]: target["id"] for target in user.call("GET", "/api/targets", params={"q": LAB})}
existing_targets = user.call("GET", "/api/targets")

def demo_target(name, value, si_ids=()):
    found = next((target for target in existing_targets if target["value"] == value), None)
    if found:
        return found["id"]
    created = user.call("POST", "/api/targets", json={"name": name, "value": value, "ports": "443", "si_ids": list(si_ids)})
    existing_targets.append(created)
    return created["id"]


cloud_target = demo_target("Cloud web service", "cloud-web.example.test", [si["Cloud Services"]])
partner_target = demo_target("Partner portal", "partner-portal.example.test", [si["Partner Network"]])
unassigned_target = demo_target("Unassigned edge service", "unassigned-edge.example.test")
existing_zones = op.call("GET", "/api/map/zones")

def map_zone(name, zone_type, cidr, si_ids, target_ids, parent_zone_id=None):
    body = {"name": name, "zone_type": zone_type, "cidr": cidr, "si_ids": si_ids,
            "target_ids": target_ids, "primary_target_ids": target_ids, "parent_zone_id": parent_zone_id}
    found = next((zone for zone in existing_zones if zone["name"] == name), None)
    if found:
        return op.call("PUT", f"/api/map/zones/{found['id']}", json=body)
    created = op.call("POST", "/api/map/zones", json=body)
    existing_zones.append(created)
    return created


public_dmz = map_zone("Public DMZ", "dmz", "192.0.2.0/24", [si["Production"]],
                      [targets_by_port["443"], targets_by_port["8443"]])
app_dmz = map_zone("Application segment", "vlan", "192.0.2.64/26", [si["Web"]],
                   [targets_by_port["8443"]], public_dmz["id"])
internal_lan = map_zone("Production LAN", "production", "198.51.100.0/24", [si["Internal"], si["Infrastructure"]],
                        [targets_by_port["8444"], targets_by_port["8445"]])
admin_net = map_zone("Administration network", "administration", "203.0.113.0/24", [si["Internal"]], [])
cloud_edge = map_zone("Cloud landing zone", "cloud", None, [si["Cloud Services"]], [])
cloud_workload = map_zone("Cloud workloads", "subnet", None, [si["Cloud Services"]], [cloud_target], cloud_edge["id"])
partner_zone = map_zone("Partner services", "partner", None, [si["Partner Network"]], [partner_target])

existing_devices = op.call("GET", "/api/map/devices")

def map_device(name, device_type, zone, ip_address, target_id=None):
    body = {"name": name, "device_type": device_type, "zone_id": zone["id"], "ip_address": ip_address,
            "target_id": target_id, "provenance": "DECLARED", "source": "CrashTest topology fixture"}
    found = next((device for device in existing_devices if device["name"] == name), None)
    if found:
        return op.call("PUT", f"/api/map/devices/{found['id']}", json=body)
    created = op.call("POST", "/api/map/devices", json=body)
    existing_devices.append(created)
    return created


edge_firewall = map_device("edge-firewall", "firewall", public_dmz, "192.0.2.1")
dmz_router = map_device("dmz-router", "router", public_dmz, "192.0.2.2")
reverse_proxy = map_device("application-proxy", "reverse_proxy", app_dmz, "192.0.2.65", targets_by_port["8443"])
core_switch = map_device("production-switch", "switch", internal_lan, "198.51.100.1")
app_server = map_device("application-server", "server", internal_lan, "198.51.100.20", targets_by_port["8444"])
admin_gateway = map_device("admin-gateway", "gateway", admin_net, "203.0.113.1")
cloud_gateway = map_device("cloud-gateway", "gateway", cloud_workload, None)
cloud_server = map_device("cloud-web-node", "server", cloud_workload, None, cloud_target)
partner_gateway = map_device("partner-gateway", "gateway", partner_zone, None)
partner_proxy = map_device("partner-reverse-proxy", "reverse_proxy", partner_zone, None, partner_target)

existing_links = op.call("GET", "/api/map/links")
link_specs = [
    (edge_firewall, dmz_router, "DECLARED", {"source": "CrashTest topology fixture"}),
    (dmz_router, reverse_proxy, "DECLARED", {"source": "CrashTest topology fixture"}),
    (core_switch, app_server, "DECLARED", {"source": "CrashTest topology fixture"}),
    (cloud_gateway, cloud_server, "OBSERVED", {"source": "CrashTest synthetic telemetry", "observed_at": "2026-10-14T12:00:00Z"}),
    (partner_gateway, partner_proxy, "INFERRED", {"source": "CrashTest synthetic topology example", "confidence": 0.72}),
]
for source, target, provenance, evidence in link_specs:
    if not any(link["source_device_id"] == source["id"] and link["target_device_id"] == target["id"] for link in existing_links):
        created = op.call("POST", "/api/map/links", json={
            "source_device_id": source["id"], "target_device_id": target["id"], "link_type": "network",
            "provenance": provenance, **evidence,
        })
        existing_links.append(created)

if not user.call("GET", "/api/schedules"):
    user.call("POST", "/api/schedules", json={"definition_id": d_https["id"], "kind": "daily", "params": {"time": "03:00"}, "timezone": "Europe/Paris"})
admin.call("PUT", "/api/admin/settings/notifications", json={"value": {"connector": "smtp", "smtp": {"host": "smtp-sink", "port": 1025, "starttls": False, "from": "tls-scan@crashtest.example.com"}}})
print("CrashTest users, TLS lab targets and Network Exposure Map fixtures are ready.")
