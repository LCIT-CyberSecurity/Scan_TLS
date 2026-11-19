"""Orion rebranding: new product identifiers, and compatibility with what installations made before it still use."""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import uuid
from pathlib import Path

import httpx
import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

from conftest import API, make_user
from orion_app.config import Settings, env_value, legacy_variables_in_use

ROOT = Path(__file__).resolve().parents[2]


# ---------- configuration: ORION_* first, TLS_SCAN_* still read ----------
def test_legacy_variable_is_read_when_the_orion_one_is_absent(monkeypatch):
    monkeypatch.delenv("ORION_MAX_SCAN_WORKERS", raising=False)
    monkeypatch.setenv("TLS_SCAN_MAX_SCAN_WORKERS", "5")
    assert Settings(environment="test").max_scan_workers == 5
    assert "TLS_SCAN_MAX_SCAN_WORKERS" in legacy_variables_in_use()


def test_orion_variable_wins_over_the_legacy_one(monkeypatch):
    monkeypatch.setenv("TLS_SCAN_MAX_SCAN_WORKERS", "5")
    monkeypatch.setenv("ORION_MAX_SCAN_WORKERS", "3")
    assert Settings(environment="test").max_scan_workers == 3
    assert "TLS_SCAN_MAX_SCAN_WORKERS" not in legacy_variables_in_use()


def test_env_value_priority_and_values_never_listed(monkeypatch):
    monkeypatch.delenv("ORION_MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("TLS_SCAN_MCP_ALLOWED_HOSTS", "legacy.example")
    assert env_value("MCP_ALLOWED_HOSTS") == "legacy.example"
    monkeypatch.setenv("ORION_MCP_ALLOWED_HOSTS", "orion.example")
    assert env_value("MCP_ALLOWED_HOSTS") == "orion.example"         # an ORION_ value wins
    monkeypatch.setenv("ORION_MCP_ALLOWED_HOSTS", "")
    assert env_value("MCP_ALLOWED_HOSTS") == "legacy.example"        # empty counts as unset, as ${VAR:-} does in Compose
    monkeypatch.setenv("TLS_SCAN_SESSION_SECRET", "sentinel-value-never-listed")
    assert "sentinel-value-never-listed" not in " ".join(legacy_variables_in_use())


def test_empty_optional_settings_from_compose_keep_their_defaults(monkeypatch):
    for name in ("SSO_AUTO_PROVISION", "OIDC_PROVIDER", "MAX_SCAN_WORKERS"):
        monkeypatch.setenv(f"ORION_{name}", "")
        monkeypatch.delenv(f"TLS_SCAN_{name}", raising=False)
    settings = Settings(environment="test")
    assert settings.sso_auto_provision is None and settings.oidc_provider == "" and settings.max_scan_workers == 8


def test_legacy_secret_file_variable_is_honoured(monkeypatch, tmp_path):
    secret = tmp_path / "session"
    secret.write_text("x" * 40, encoding="utf-8")
    monkeypatch.delenv("ORION_SESSION_SECRET_FILE", raising=False)
    monkeypatch.delenv("ORION_SESSION_SECRET", raising=False)
    monkeypatch.setenv("TLS_SCAN_SESSION_SECRET_FILE", str(secret))
    assert Settings(environment="test").session_secret == "x" * 40


def test_new_installation_defaults_use_orion_names(monkeypatch):
    for name in ("ORION_DATABASE_URL", "TLS_SCAN_DATABASE_URL", "ORION_STORAGE_ROOT", "TLS_SCAN_STORAGE_ROOT"):
        monkeypatch.delenv(name, raising=False)
    settings = Settings(environment="test")
    assert settings.database_url.endswith("/orion") and settings.storage_root == "/var/lib/orion"


# ---------- deprecated Python package alias ----------
def test_tls_scan_app_alias_returns_the_same_modules():
    with pytest.warns(DeprecationWarning):
        legacy = importlib.import_module("tls_scan_app")
    import orion_app.config
    import orion_app.models
    import tls_scan_app.config
    from tls_scan_app.models import User
    assert legacy is not None and tls_scan_app.config is orion_app.config and User is orion_app.models.User
    assert orion_app.config.__spec__.name == "orion_app.config"     # the real module keeps its own identity


def test_tls_scan_app_alias_runs_the_commands():
    result = subprocess.run([sys.executable, "-W", "ignore::DeprecationWarning", "-m", "tls_scan_app.cli", "--help"],
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0 and "reset-admin-password" in result.stdout, result.stderr


def test_former_standalone_entry_point_is_kept():
    for script in ("orion.py", "tls_scan.py"):
        result = subprocess.run([sys.executable, str(ROOT / script), "--help"], capture_output=True, text=True, timeout=60,
                                cwd=ROOT, check=False)
        assert result.returncode == 0 and "--config" in result.stdout, (script, result.stderr)


# ---------- deployment files ----------
def test_every_compose_setting_falls_back_to_its_legacy_name():
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    names = set(re.findall(r"\$\{ORION_([A-Z0-9_]+):-", compose)) - {"DB_NAME", "DB_USER"}
    assert names, "compose.yaml must use ORION_* settings"
    for name in names:
        assert f"${{ORION_{name}:-${{TLS_SCAN_{name}:-" in compose, name
    assert "orion-backend:" in compose and "orion-webui:" in compose and "/var/lib/orion" in compose


def test_env_example_has_no_legacy_names():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert not re.search(r"^TLS_SCAN_", example, re.M)
    assert re.search(r"^ORION_DB_NAME=orion$", example, re.M) and re.search(r"^ORION_PROJECT=orion$", example, re.M)


# ---------- migration 0024 (applied on a throw-away SQLite database) ----------
def load_migration():
    path = ROOT / "backend/migrations/versions/0024_orion_product_identity.py"
    spec = importlib.util.spec_from_file_location("migration_0024", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_migration(engine, step: str) -> None:
    migration = load_migration()
    with engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            getattr(migration, step)()


def test_migration_frees_the_builtin_name_reversibly_and_idempotently():
    engine = sa.create_engine("sqlite://")
    metadata = sa.MetaData()
    stores = sa.Table("trust_stores", metadata, sa.Column("id", sa.Uuid, primary_key=True), sa.Column("name", sa.String(120), unique=True))
    settings = sa.Table("system_settings", metadata, sa.Column("key", sa.String(80), primary_key=True), sa.Column("value", sa.JSON))
    metadata.create_all(engine)
    conflicting, other = uuid.uuid4(), uuid.uuid4()
    with engine.begin() as connection:
        connection.execute(stores.insert(), [{"id": conflicting, "name": "orion public web pki"},
                                             {"id": other, "name": "Internal CA"}])
        connection.execute(settings.insert(), [{"key": "auth", "value": {"provider": "none"}}])

    run_migration(engine, "upgrade")
    run_migration(engine, "upgrade")                                   # idempotent
    with engine.connect() as connection:
        names = dict(connection.execute(sa.select(stores.c.id, stores.c.name)).all())
        record = connection.execute(sa.select(settings.c.value).where(settings.c.key == "product_identity")).scalar_one()
        untouched = connection.execute(sa.select(settings.c.value).where(settings.c.key == "auth")).scalar_one()
    assert names == {conflicting: "orion public web pki (custom)", other: "Internal CA"}
    assert record["product"] == "Orion" and record["renamed_trust_stores"] == [
        {"id": str(conflicting), "from": "orion public web pki", "to": "orion public web pki (custom)"}]
    assert untouched == {"provider": "none"}

    run_migration(engine, "downgrade")
    with engine.connect() as connection:
        names = dict(connection.execute(sa.select(stores.c.id, stores.c.name)).all())
        keys = set(connection.execute(sa.select(settings.c.key)).scalars())
    assert names == {conflicting: "orion public web pki", other: "Internal CA"} and keys == {"auth"}


# ---------- sessions opened before the rebranding ----------
def test_session_cookie_from_before_the_rebranding_is_still_honoured(admin):
    fresh = make_user(admin, "USER")
    raw = fresh.http.cookies.get("orion_session")
    assert raw and fresh.http.cookies.get("tls_scan_session") is None
    legacy = httpx.Client(base_url=API, cookies={"tls_scan_session": raw}, timeout=30)
    assert legacy.get("/api/auth/me").status_code == 200
    assert httpx.get(f"{API}/api/auth/me", cookies={"tls_scan_session": "forged"}, timeout=30).status_code == 401
    logout = legacy.post("/api/auth/logout", headers={"x-csrf-token": fresh.csrf})
    assert logout.status_code == 200
    assert legacy.get("/api/auth/me").status_code == 401


# ---------- report template branding on Orion reports and on reports generated before the rebranding ----------
@pytest.mark.parametrize("mark", ["O", "TS"])
def test_template_logo_replaces_the_report_mark(tmp_path, mark):
    from orion_app.services.report_branding import apply_to_html
    report = tmp_path / "report.html"
    report.write_text(f'<html><head></head><body><div class="brand-mark large" aria-hidden="true">{mark}</div></body></html>', encoding="utf-8")
    assert apply_to_html(report, {"logo": "data:image/png;base64,AAAA"})
    text = report.read_text(encoding="utf-8")
    assert 'src="data:image/png;base64,AAAA"' in text and "brand-mark" not in text
