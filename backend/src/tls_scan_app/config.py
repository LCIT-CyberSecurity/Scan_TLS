"""Runtime configuration of the WebUI application, read from TLS_SCAN_* environment variables."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SECRET = 32
_DEV_SECRETS = frozenset({"", "change-me-to-a-long-random-value", "dev-only-insecure-secret-change-me"})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TLS_SCAN_", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "postgresql+psycopg://tls_scan:tls_scan@localhost:5432/tls_scan"
    log_level: str = "INFO"
    public_base_url: str = "http://localhost:8000"

    session_secret: str = "dev-only-insecure-secret-change-me"  # noqa: S105
    cookie_secure: bool = True
    session_idle_timeout_minutes: int = 60
    session_absolute_timeout_hours: int = 12

    # Local administrator: created at first start with a generated one-time password
    # (written to a file, never logged) unless one is provided; must be changed at first login.
    local_admin_username: str = "admin"
    local_admin_password: str = ""  # noqa: S105
    local_admin_password_file: str = ""
    initial_password_path: str = "/var/lib/tls-scan/initial-admin-password"
    session_secret_file: str = ""
    smtp_password: str = ""  # noqa: S105
    graph_client_secret: str = ""  # noqa: S105
    graph_client_secret_file: str = ""
    # Overridable only so tests can point at a mock; defaults are the public Microsoft endpoints.
    graph_login_url: str = "https://login.microsoftonline.com"
    graph_base_url: str = "https://graph.microsoft.com/v1.0"
    smtp_password_file: str = ""

    # OIDC (Entra ID or generic). Empty issuer = SSO disabled.
    oidc_provider: Literal["", "entra", "generic"] = ""
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""  # noqa: S105
    oidc_default_role: Literal["AUDITOR", "USER", "OPERATOR"] = "USER"
    crashtest: bool = False

    # Where reports and raw results live (hybrid storage: files here, structure in PostgreSQL).
    storage_root: str = "/var/lib/tls-scan"
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
            self.session_secret = Path(self.session_secret_file).read_text(encoding="utf-8").strip()
        if self.graph_client_secret_file:
            self.graph_client_secret = Path(self.graph_client_secret_file).read_text(encoding="utf-8").strip()
        if self.smtp_password_file:
            self.smtp_password = Path(self.smtp_password_file).read_text(encoding="utf-8").strip()
        if self.local_admin_password_file:
            self.local_admin_password = Path(self.local_admin_password_file).read_text(encoding="utf-8").strip()
        return self

    @model_validator(mode="after")
    def _production_secrets(self) -> Settings:
        if self.environment != "production":
            return self
        problems = []
        if self.session_secret in _DEV_SECRETS or len(self.session_secret) < MIN_SECRET:
            problems.append(f"TLS_SCAN_SESSION_SECRET is empty, short (< {MIN_SECRET}) or a development value")
        if not self.cookie_secure:
            problems.append("TLS_SCAN_COOKIE_SECURE must be true")
        if problems:
            raise ValueError("Refusing to start in production: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
