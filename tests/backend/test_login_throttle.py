"""Login throttling needs the limiter ON, which the shared test stack disables; it is exercised in-process."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tls_scan_app.api import auth
from tls_scan_app.config import Settings
from tls_scan_app.services.rate_limit import SlidingWindowLimiter


class FakeDb:  # no account exists: every attempt is a failure
    def execute(self, *_a, **_k):
        class R:
            def scalars(self_inner):
                return self_inner

            def first(self_inner):
                return None

        return R()

    def add(self, *_):
        pass

    def commit(self):
        pass


def test_failures_lock_the_account_but_not_the_neighbour():
    app = FastAPI()
    app.state.settings = Settings(rate_limit_enabled=True, environment="test")
    app.state.limiter = SlidingWindowLimiter()
    app.include_router(auth.router)
    app.dependency_overrides[auth.get_db] = lambda: FakeDb()
    client = TestClient(app)
    codes = [client.post("/api/auth/login", json={"username": "victim", "password": "x" * 14}).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    assert client.post("/api/auth/login", json={"username": "someone-else", "password": "x" * 14}).status_code == 401
