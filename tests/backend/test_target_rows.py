"""Bulk target entry uses the same catalog and permissions as single creation."""
import uuid


def test_mixed_target_rows(user, operator):
    suffix = uuid.uuid4().hex[:8]
    si = operator.post("/api/information-systems", json={"name": f"Rows {suffix}"})
    assert si.status_code == 201, si.text
    si_id = si.json()["id"]
    host = f"rows-{suffix}.example.org"
    existing = user.post("/api/targets", json={"value": host, "description": "original"})
    assert existing.status_code == 201
    response = user.post("/api/targets/rows", json={
        "values": ["192.0.2.135", f"2001:db8::{suffix[:4]}", "198.51.100.25/24",
                   "198.51.100.0/24", host.upper() + ".", "", "invalid/99", f"new-{host}"],
        "name": "Shared label", "tags": [f"rows-{suffix}"], "si_ids": [si_id], "ports": "8443",
    })
    assert response.status_code == 200, response.text
    rows = response.json()
    assert [row["status"] for row in rows] == [
        "created", "created", "created", "duplicate", "existing", "invalid", "invalid", "created",
    ]
    created = [row["target"] for row in rows if row["status"] == "created"]
    assert [row["kind"] for row in created] == ["ip", "ip", "cidr", "fqdn"]
    assert created[2]["value"] == "198.51.100.0/24"
    for row in created:
        assert (row["name"], row["ports"], row["tags"], row["si_ids"]) == (
            "Shared label", "8443", [f"rows-{suffix}"], [si_id],
        )
    assert next(row for row in user.get("/api/targets", params={"q": host}).json() if row["value"] == host)["description"] == "original"
    assert all(group["name"] != "Shared label" for group in user.get("/api/target-groups").json())
    for row in created:
        assert user.delete(f"/api/targets/{row['id']}").status_code == 204


def test_target_rows_limits_and_permissions(user, auditor):
    assert user.post("/api/targets/rows", json={"values": ["example.org"] * 51}).status_code == 422
    assert user.post("/api/targets/rows", json={"values": []}).status_code == 422
    assert auditor.post("/api/targets/rows", json={"values": ["example.org"]}).status_code == 403
