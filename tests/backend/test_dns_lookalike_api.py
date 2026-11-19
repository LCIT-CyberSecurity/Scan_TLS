from orion_app.api import catalog
from orion_app.config import get_settings
from orion_app.database import make_engine, make_session_factory
from orion_app.models import DnsDiscovery


def test_monitor_routes_are_admin_guarded_and_default_to_paused() -> None:
    routes = {
        (route.path, method): route
        for route in catalog.router.routes
        for method in route.methods or ()
        if route.path.startswith("/api/dns-lookalike-monitors")
    }

    assert routes
    assert all(any(dependency.call is catalog.administrator for dependency in route.dependant.dependencies)
               for route in routes.values())
    assert catalog.LookalikeMonitorBody(domain="example.com", authorized=True).enabled is False


def test_lookalike_runs_do_not_open_as_discovery_results(admin) -> None:
    settings = get_settings()
    factory = make_session_factory(make_engine(settings.database_url, settings.database_password_file))
    with factory() as db:
        discovery = DnsDiscovery(domain="example.org", status="done", options=None, result={"observations": []})
        monitoring = DnsDiscovery(
            domain="example.org", status="done", options={"lookalike_monitor_id": "fixture"},
            result={"observations": [{"domain": "examp1e.org", "dns_status": "resolved"}]},
        )
        db.add_all([discovery, monitoring])
        db.commit()
        try:
            response = admin.get("/api/targets/discover")
            assert response.status_code == 200
            listed = {row["id"] for row in response.json()}
            assert str(discovery.id) in listed
            assert str(monitoring.id) not in listed

            response = admin.get(f"/api/targets/discover/{monitoring.id}/results")
            assert response.status_code == 409
            assert "historique" in response.json()["detail"]
        finally:
            db.delete(discovery)
            db.delete(monitoring)
            db.commit()
