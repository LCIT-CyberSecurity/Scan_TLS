from tls_scan_app.api import catalog


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
