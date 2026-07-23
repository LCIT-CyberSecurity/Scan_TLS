"""Domain models and package-level exceptions."""

from dataclasses import dataclass

from .constants import DEFAULT_EXPORT_DIR, DEFAULT_LOG_FILE


class PQCPrerequisiteError(RuntimeError):
    pass


class ConfigError(RuntimeError):
    pass


@dataclass
class TargetGroup:
    name: str
    targets: tuple[str, ...]
    description: str = ""
    path: str = ""


@dataclass
class EncryptionPolicy:
    name: str
    version: str = ""
    description: str = ""
    path: str = ""


@dataclass
class ScanJob:
    targets: str
    ports: str
    crypto: str
    ip: bool
    csv_filename: str | None = None
    export_format: str | None = None
    pqc_groups: tuple[str, ...] = ()
    log_level: str = "info"
    log_file: str | None = DEFAULT_LOG_FILE
    scan_run_id: str = ""
    report_name: str = "manual"
    frequency: str = "manual"
    target_groups: tuple[TargetGroup, ...] = ()
    policies: tuple[EncryptionPolicy, ...] = ()
    policy_mode: str = "strict_all"
    export_directory: str = DEFAULT_EXPORT_DIR
    export_formats: tuple[str, ...] = ()
    filename_template: str = "{timestamp}_{report_name}"
    dry_run: bool = False
