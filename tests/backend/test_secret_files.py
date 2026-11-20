from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from orion_app.config import Settings
from orion_app.database import make_engine

ROOT = Path(__file__).resolve().parents[2]


def test_settings_reads_secret_file_and_never_echoes_contents(tmp_path: Path) -> None:
    secret = "sentinel-session-password"
    file = tmp_path / "session"
    file.write_text(secret, encoding="utf-8")

    settings = Settings(environment="test", session_secret_file=str(file))

    assert settings.session_secret == secret
    assert secret not in repr(settings)


def test_missing_secret_file_reports_kind_without_exposing_secret(tmp_path: Path) -> None:
    missing = tmp_path / "missing-file"

    with pytest.raises(ValueError, match="session secret file.*FileNotFoundError") as error:
        Settings(environment="test", session_secret_file=str(missing))

    assert "FileNotFoundError" in str(error.value)


def test_production_background_service_can_start_without_api_session_secret() -> None:
    settings = Settings(environment="production", cookie_secure=True, session_secret_required=False)

    assert settings.session_secret_required is False


def test_production_requires_a_strong_session_secret_by_default() -> None:
    with pytest.raises(ValueError, match="ORION_SESSION_SECRET"):
        Settings(environment="production", cookie_secure=True)


def test_database_password_file_is_applied_without_injecting_it_in_compose_url(tmp_path: Path) -> None:
    password = " p@ss:/db?word "
    file = tmp_path / "database"
    file.write_text(password, encoding="utf-8")

    engine = make_engine("postgresql+psycopg://orion@postgres:5432/orion", str(file))

    assert engine.url.password == password
    assert password not in engine.url.render_as_string(hide_password=True)
    engine.dispose()


def test_database_password_file_missing_or_empty_fails_without_revealing_content(tmp_path: Path) -> None:
    missing = tmp_path / "not-there"
    with pytest.raises(RuntimeError, match="Database password file is unavailable"):
        make_engine("postgresql+psycopg://orion@postgres/orion", str(missing))

    empty = tmp_path / "empty"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Database password file is empty"):
        make_engine("postgresql+psycopg://orion@postgres/orion", str(empty))


def test_alembic_uses_the_database_password_file() -> None:
    migration_environment = (ROOT / "backend/migrations/env.py").read_text(encoding="utf-8")
    assert "make_engine(settings.database_url, settings.database_password_file)" in migration_environment
    assert "create_engine(" not in migration_environment


def test_compose_grants_file_secrets_only_to_consumers() -> None:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]

    def secret_names(service: str) -> set[str]:
        return {item if isinstance(item, str) else item["source"] for item in services[service].get("secrets", [])}

    assert all("env_file" not in service for service in services.values())
    assert "POSTGRES_PASSWORD_FILE" in services["postgres"]["environment"]
    assert "POSTGRES_PASSWORD" not in services["postgres"]["environment"]
    # Compose resolves ${VAR:-default}; the resolved URL must carry a user name and no password.
    database_url = re.sub(r"\$\{[A-Z0-9_]+:-([^}]*)\}", r"\1", services["api"]["environment"]["ORION_DATABASE_URL"])
    assert database_url == "postgresql+psycopg://orion@postgres:5432/orion"
    assert ":" not in database_url.split("@", 1)[0].split("://", 1)[1]
    assert secret_names("postgres") == {"postgres_password"}
    assert {"database_password", "session_secret", "oidc_client_secret", "greenbone_password", "snmp_v3_auth_key"} <= secret_names("api")
    assert {"database_password", "smtp_password", "graph_client_secret", "snmp_v3_auth_key"} <= secret_names("worker")
    assert {"database_password", "smtp_password", "graph_client_secret"} == secret_names("scheduler")
    assert services["worker"]["environment"]["ORION_SESSION_SECRET_REQUIRED"] == "false"
    assert services["scheduler"]["environment"]["ORION_SESSION_SECRET_REQUIRED"] == "false"
    assert "oidc_client_secret" not in secret_names("worker") | secret_names("scheduler")
    # The worker runs the read-only Greenbone imports (LST-24) and needs the GMP password; the scheduler never does.
    assert "greenbone_password" in secret_names("worker") and "greenbone_password" not in secret_names("scheduler")
    assert secret_names("webui") == set()
    assert "no-new-privileges:true" in services["api"]["security_opt"]
    assert services["api"]["cap_drop"] == ["ALL"]


def test_example_env_has_no_direct_secret_values() -> None:
    content = (ROOT / ".env.example").read_text(encoding="utf-8")
    for line in content.splitlines():
        if line.lstrip().startswith("#") or "=" not in line:
            continue
        key, _ = line.split("=", 1)
        assert not any(token in key for token in ("PASSWORD", "CLIENT_SECRET", "AUTH_KEY", "PRIV_KEY")), key
