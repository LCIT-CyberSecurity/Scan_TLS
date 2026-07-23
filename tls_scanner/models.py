"""
Domain models and package-level exceptions.

Called by:
- configuration, CLI, export, and test modules;
- the public facade in `tls_scanner.__init__`.

Produces:
- the `ScanJob`, `TargetGroup`, and `EncryptionPolicy` dataclasses;
- the domain exceptions `ConfigError` and `PQCPrerequisiteError`.
"""

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
    allowed_versions: tuple[str, ...] = ()
    allowed_cipher_algorithms: tuple[str, ...] = ()
    allowed_signature_hashes: tuple[str, ...] = ()
    minimum_rsa_bits: int = 2048


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
