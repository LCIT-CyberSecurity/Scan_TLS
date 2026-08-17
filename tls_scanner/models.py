"""
Domain models and package-level exceptions.

Called by:
- configuration, CLI, export, and test modules;
- the public facade in `tls_scanner.__init__`.

Produces:
- the `ScanJob`, `TargetGroup`, and `EncryptionPolicy` dataclasses;
- the domain exceptions `ConfigError` and `PQCPrerequisiteError`.
"""

from dataclasses import dataclass, field
from typing import Any

from .constants import DEFAULT_EXPORT_DIR, DEFAULT_LOG_FILE, DEFAULT_WORKERS


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
class CertificateInfo:
    subject: str = "-"
    issuer: str = "-"
    subject_alternative_names: tuple[str, ...] = ()
    not_after: str = "N/A"
    days_remaining: int | None = None
    public_key_type: str = "Unknown"
    public_key_bits: int | None = None
    signature_algorithm: str = ""
    self_signed: str = "unknown"


@dataclass
class TrustStoreConfig:
    name: str
    store_type: str
    path: str = ""


@dataclass
class LoadedTrustStore:
    store_id: str
    store_name: str
    store_type: str
    source: str
    certificates: tuple[Any, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TrustStoreValidation:
    store_id: str
    store_name: str
    store_type: str
    status: str
    validation_error: str = ""
    trust_anchor_subject: str = ""
    verified_chain_length: int | None = None


@dataclass(frozen=True)
class CertificateTrustResult:
    trust_classification: str
    trusted_by: tuple[str, ...] = ()
    trust_anchor: str = ""
    chain_validation_status: str = "Not Tested"
    trust_store_results: tuple[TrustStoreValidation, ...] = ()


@dataclass
class CertificateRevocationResult:
    revocation_status: str = "Not Tested"
    ocsp_status: str = "Not Tested"
    crl_status: str = "Not Tested"
    details: tuple[str, ...] = ()


@dataclass
class SecurityFinding:
    ip: str
    fqdn: str
    port: int | str
    check: str
    status: str
    severity: str
    evidence: str
    remediation: str


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
    workers: int = DEFAULT_WORKERS
    certificate_findings_enabled: bool = True
    certificate_expires_within_days: int = 30
    certificate_trust_enabled: bool = True
    certificate_public_trust_store_enabled: bool = True
    certificate_trust_stores: tuple[LoadedTrustStore, ...] = ()
    certificate_trust_results: dict[str, CertificateTrustResult] = field(default_factory=dict)
    certificate_revocation_enabled: bool = False
    certificate_revocation_ocsp_enabled: bool = True
    certificate_revocation_crl_enabled: bool = True
    certificate_revocation_timeout_seconds: int = 5
    certificate_revocation_max_response_bytes: int = 1048576
    certificate_revocation_allow_private_urls: bool = False
    certificate_revocation_results: dict[str, CertificateRevocationResult] = field(default_factory=dict)
