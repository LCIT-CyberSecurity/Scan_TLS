"""Runtime configuration of the WebUI application, read from ORION_* environment variables.

Installations from before the Orion rebranding still set TLS_SCAN_*: each legacy variable is read only when its ORION_*
counterpart is absent or empty, so an explicit ORION_* value always wins. Legacy names are reported (never their values)
at start. An empty variable counts as unset, as `${VAR:-default}` does in Compose, which passes "" for an unset optional
setting (a boolean such as ORION_SSO_AUTO_PROVISION would otherwise refuse to start).
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, EnvSettingsSource, PydanticBaseSettingsSource, SettingsConfigDict

MIN_SECRET = 32
_DEV_SECRETS = frozenset({"", "change-me-to-a-long-random-value", "dev-only-insecure-secret-change-me"})
ENV_PREFIX = "ORION_"
LEGACY_ENV_PREFIX = "TLS_SCAN_"

logger = logging.getLogger("orion_app.config")


def env_value(name: str, default: str = "") -> str:
    """ORION_<name> when it is set and not empty, else the legacy TLS_SCAN_<name>, else the default."""
    return os.environ.get(ENV_PREFIX + name) or os.environ.get(LEGACY_ENV_PREFIX + name) or default


def legacy_variables_in_use() -> list[str]:
    """Names of the TLS_SCAN_* variables actually used because no ORION_* variable replaces them."""
    return sorted(name for name in os.environ
                  if name.startswith(LEGACY_ENV_PREFIX) and os.environ[name] and not os.environ.get(ENV_PREFIX + name[len(LEGACY_ENV_PREFIX):]))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix=ENV_PREFIX, extra="ignore", env_ignore_empty=True)

    @classmethod
    def settings_customise_sources(cls, settings_cls: type[BaseSettings], init_settings: PydanticBaseSettingsSource,
                                   env_settings: PydanticBaseSettingsSource, dotenv_settings: PydanticBaseSettingsSource,
                                   file_secret_settings: PydanticBaseSettingsSource) -> tuple[PydanticBaseSettingsSource, ...]:
        legacy_env = EnvSettingsSource(settings_cls, env_prefix=LEGACY_ENV_PREFIX)
        return init_settings, env_settings, legacy_env, dotenv_settings, file_secret_settings

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "postgresql+psycopg://orion:orion@localhost:5432/orion"
    database_password_file: str = ""
    log_level: str = "INFO"
    public_base_url: str = "http://localhost:8000"

    session_secret: str = Field(default="dev-only-insecure-secret-change-me", repr=False)
    session_secret_required: bool = True
    cookie_secure: bool = True
    session_idle_timeout_minutes: int = 60
    session_absolute_timeout_hours: int = 12

    # Local administrator: created at first start with the deployment default password
    # ("SecretPassword") unless one is provided; must be changed at first login.
    local_admin_username: str = "admin"
    local_admin_password: str = Field(default="", repr=False)
    local_admin_password_file: str = ""
    session_secret_file: str = ""
    smtp_password: str = Field(default="", repr=False)
    graph_client_secret: str = Field(default="", repr=False)
    directory_client_secret: str = Field(default="", repr=False)
    directory_client_secret_file: str = ""
    ldap_bind_password: str = Field(default="", repr=False)
    ldap_bind_password_file: str = ""
    # Exact host allowlist for outbound read-only GMP connections (comma-separated).
    greenbone_allowed_hosts: str = ""
    greenbone_username: str = ""
    greenbone_password: str = Field(default="", repr=False)
    greenbone_password_file: str = ""
    greenbone_credential_key_file: str = ""
    greenbone_ca_file: str = ""
    greenbone_client_cert_file: str = ""
    greenbone_client_key_file: str = ""
    graph_client_secret_file: str = ""
    # Overridable only so tests can point at a mock; defaults are the public Microsoft endpoints.
    graph_login_url: str = "https://login.microsoftonline.com"
    graph_base_url: str = "https://graph.microsoft.com/v1.0"
    smtp_password_file: str = ""
    # Optional read-only SNMPv3 authPriv credentials, provisioned through server environment/files only.
    snmp_v3_username: str = ""
    snmp_v3_auth_key: str = Field(default="", repr=False)
    snmp_v3_auth_key_file: str = ""
    snmp_v3_priv_key: str = Field(default="", repr=False)
    snmp_v3_priv_key_file: str = ""

    # OIDC (Entra ID or generic). Empty issuer = SSO disabled.
    oidc_provider: Literal["", "entra", "generic"] = ""
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = Field(default="", repr=False)
    oidc_client_secret_file: str = ""
    oidc_default_role: Literal["AUDITOR", "USER", "OPERATOR"] = "USER"
    # Google Workspace sign-in (OIDC). The secret is only ever read from the environment or a protected file.
    google_client_secret: str = Field(default="", repr=False)
    google_client_secret_file: str = ""
    google_issuer: str = ""          # overridable only so tests can point at a mock; empty = accounts.google.com
    google_directory_key_file: str = ""   # service-account key (JSON) for the read-only Admin SDK directory lookup
    # Create the account of a first-time SSO / LDAP user on the fly (with the default role)? None = not set in the environment.
    sso_auto_provision: bool | None = None
    crashtest: bool = False

    # Where reports and raw results live (hybrid storage: files here, structure in PostgreSQL).
    storage_root: str = "/var/lib/orion"
    max_concurrent_scans: int = 2
    max_scan_duration_seconds: int = 3600
    max_targets_per_scan: int = 4096  # total addresses (CIDRs expanded) per scan
    max_scan_workers: int = 8
    worker_poll_seconds: float = 2.0
    scheduler_poll_seconds: float = 15.0
    rate_limit_enabled: bool = True
    timezone: str = "Europe/Paris"

    @model_validator(mode="after")
    def _load_files(self) -> Settings:
        if self.session_secret_file:
            self.session_secret = _read_secret(self.session_secret_file, "session secret")
        for name in ("directory_client_secret", "ldap_bind_password", "greenbone_password"):
            path = getattr(self, f"{name}_file")
            if path:
                setattr(self, name, _read_secret(path, name.replace("_", " ")))
        if self.graph_client_secret_file:
            self.graph_client_secret = _read_secret(self.graph_client_secret_file, "Graph client secret")
        if self.oidc_client_secret_file:
            self.oidc_client_secret = _read_secret(self.oidc_client_secret_file, "OIDC client secret")
        if self.google_client_secret_file:
            self.google_client_secret = _read_secret(self.google_client_secret_file, "Google client secret")
        if self.smtp_password_file:
            self.smtp_password = _read_secret(self.smtp_password_file, "SMTP password")
        if self.local_admin_password_file:
            self.local_admin_password = _read_secret(self.local_admin_password_file, "local administrator password")
        for name in ("snmp_v3_auth_key", "snmp_v3_priv_key"):
            path = getattr(self, f"{name}_file")
            if path:
                setattr(self, name, _read_secret(path, name.replace("_", " ")))
        return self

    @model_validator(mode="after")
    def _production_secrets(self) -> Settings:
        if self.environment != "production":
            return self
        problems = []
        if self.session_secret_required and (self.session_secret in _DEV_SECRETS or len(self.session_secret) < MIN_SECRET):
            problems.append(f"ORION_SESSION_SECRET is empty, short (< {MIN_SECRET}) or a development value")
        if not self.cookie_secure:
            problems.append("ORION_COOKIE_SECURE must be true")
        if problems:
            raise ValueError("Refusing to start in production: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    legacy = legacy_variables_in_use()
    if legacy:
        logger.warning("Deprecated TLS_SCAN_* configuration in use (rename to ORION_*): %s", ", ".join(legacy))
    return Settings()


def _read_secret(path: str, label: str) -> str:
    """Read a mounted secret without ever including its contents in an error message."""
    try:
        return Path(path).read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as error:
        raise ValueError(f"Unable to read configured {label} file ({error.__class__.__name__})") from None
