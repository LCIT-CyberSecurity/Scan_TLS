"""Pydantic response models of the read-only results API (`/api/results`)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from tls_scan_app.api import results_examples as ex


def example(value: Any) -> ConfigDict:
    return ConfigDict(json_schema_extra={"examples": [value]})


RunStatus = Literal["scheduled", "queued", "running", "completed", "partial", "failed", "cancelled", "expired"]
Severity = Literal["critical", "high", "medium", "low", "informational"]
ReportFormat = Literal["html", "md", "csv", "findings_csv", "cbom", "metadata"]


class Pagination(BaseModel):
    model_config = example(ex.PAGE)
    total: int = Field(description="Number of items matching the filters.")
    limit: int = Field(description="Page size used.")
    offset: int = Field(description="Index of the first returned item.")


class SeverityCount(BaseModel):
    unique: int = Field(description="Distinct findings of this severity.")
    occurrences: int = Field(description="Finding occurrences (finding x affected endpoint).")


class RunSummary(BaseModel):
    """Statistics computed by the TLS engine at the end of the scan. Absent (null on the run) until the scan has produced results."""
    model_config = example(ex.SUMMARY)

    total_hosts: int
    total_endpoints: int = Field(description="TLS services analysed.")
    compliant_endpoints: int
    non_compliant_endpoints: int
    endpoints_with_errors: int
    endpoints_not_fully_tested: int
    unique_findings: int
    finding_occurrences: int
    findings_by_severity: dict[str, SeverityCount]
    checks_not_tested: int = Field(description="Total of checks that could not be run, over all endpoints.")
    overall_grade: str | None = Field(None, description="Worst grade among the endpoints, as computed by the engine.")
    compliance_status: str | None = Field(None, description="Overall status computed by the engine.")


class ReportInfo(BaseModel):
    model_config = example(ex.REPORT)
    format: ReportFormat
    size: int | None = Field(None, description="Size in bytes, as recorded when the report was generated.")
    sha256: str = Field(description="SHA-256 recorded at generation; verified on every download.")
    content_type: str
    available: bool = Field(description="False when the file is no longer on disk (download would return 404).")
    download_url: str


class Certificate(BaseModel):
    """Only the attributes actually collected by the scan; anything not collected is null."""
    model_config = example(ex.CERT)

    subject: str | None = None
    issuer: str | None = None
    valid_until: str | None = Field(None, description="Expiry date (notAfter) as recorded by the engine. The start of validity is not collected.")
    remaining_days: int | None = None
    key_type: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None
    fingerprint: str | None = Field(None, description="Certificate fingerprint.")
    trust_status: str | None = None
    chain_validation_status: str | None = None
    revocation_status: str | None = None
    self_signed: bool | None = None
    status: str | None = Field(None, description="Engine verdict on the certificate (e.g. Valid, Expired).")


class TlsCheck(BaseModel):
    """Result of one complementary TLS check. Reported next to, never inside, the grade and the findings."""
    check_id: str = Field(description="Stable check identifier (e.g. hostname_san, ocsp_stapling, tls_compression).")
    status: Literal["PASS", "FAIL", "NOT_TESTED", "NOT_APPLICABLE", "INCONCLUSIVE", "ERROR"] = Field(
        description="NOT_TESTED, INCONCLUSIVE and ERROR mean unknown, not passed.")
    message: str = ""
    observations: dict[str, Any] = Field({}, description="Structured technical observations proven by the check.")
    evidence: list[str] = Field([], description="Short, non-sensitive facts supporting the result.")
    duration_ms: int | None = None


class Endpoint(BaseModel):
    model_config = example(ex.ENDPOINT)
    endpoint_id: str = Field(description="Stable identifier `ip:port/tcp`.")
    hostname: str | None = Field(None, description="FQDN, when the target was a name.")
    ip_address: str | None = None
    port: int | None = None
    grade: str | None = None
    compliance_status: str | None = Field(None, description="compliant, non_compliant, error or not_tested.")
    highest_severity: str | None = Field(None, description="critical, high, medium, low or informational.")
    tls_versions: list[str] = []
    cipher_suites: list[str] = []
    certificate: Certificate | None = None
    errors: list[str] = Field([], description="Technical errors met while scanning this endpoint.")
    untested_checks: list[str] = Field([], description="Checks that could not be run. They are unknown, not passed.")
    tls_checks: list[TlsCheck] = Field([], description="Complementary TLS checks selected by the scan profile; empty when none was selected.")
    tags: list[str] = []


class Finding(BaseModel):
    model_config = example(ex.FINDING)
    finding_id: str = Field(description="Engine identifier of the finding (e.g. CERTIFICATE_SELF_SIGNED).")
    title: str
    category: str | None = None
    severity: Severity | None = None
    status: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    affected_endpoint_ids: list[str] = []


class PolicyVersionRef(BaseModel):
    name: str
    version: int | str
    version_id: uuid.UUID


class NamedRef(BaseModel):
    id: uuid.UUID
    name: str | None = Field(None, description="Null if the object has been deleted since.")


class Run(BaseModel):
    model_config = example(ex.RUN)
    id: uuid.UUID
    name: str
    status: RunStatus
    phase: str | None = None
    definition: NamedRef | None = Field(None, description="Scan definition; null if it was deleted.")
    initiated_by: uuid.UUID | None = None
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    tags: list[str] = Field([], description="Tags of the scan definition.")
    information_systems: list[uuid.UUID] = Field([], description="SI / sub-SI the definition is attached to.")
    summary: RunSummary | None = None


class RunDetail(Run):
    model_config = example(ex.RUN_DETAIL)
    profile: NamedRef | None = Field(None, description="Scan profile used (version in `profile_version`).")
    profile_version: int | str | None = None
    policy_versions: list[PolicyVersionRef] = []
    progress: dict[str, Any] | None = None
    error: str | None = Field(None, description="Run-level execution error.")
    endpoint_errors: dict[str, list[str]] = Field({}, description="Errors per endpoint_id (endpoints without error are omitted).")
    untested_checks: dict[str, list[str]] = Field({}, description="Checks not performed, per endpoint_id.")
    skipped_hosts: list[Any] = Field([], description="Hosts the scan could not process.")
    reports: list[ReportInfo] = []


class RunPage(BaseModel):
    model_config = example({'items': [ex.RUN], 'pagination': ex.PAGE})
    items: list[Run]
    pagination: Pagination


class EndpointPage(BaseModel):
    model_config = example({'items': [ex.ENDPOINT], 'pagination': ex.PAGE})
    items: list[Endpoint]
    pagination: Pagination


class FindingPage(BaseModel):
    model_config = example({'items': [ex.FINDING], 'pagination': ex.PAGE})
    items: list[Finding]
    pagination: Pagination


class ReportList(BaseModel):
    model_config = example({'items': [ex.REPORT]})
    items: list[ReportInfo]


class FindingGroup(BaseModel):
    finding_id: str
    title: str
    severity: Severity | None = None
    affected: list[str] = Field(description="Affected endpoint ids.")


class EndpointChange(BaseModel):
    """What differs for one endpoint present in both runs. Only the changed aspects are present."""

    model_config = ConfigDict(extra="allow")
    endpoint_id: str
    tls_versions: dict[str, Any] | None = Field(None, description="{before, after}")
    cipher_suites: dict[str, Any] | None = Field(None, description="{added, removed}")
    certificate: dict[str, Any] | None = None
    compliance: dict[str, Any] | None = None
    new_errors: list[str] | None = None


class ComparisonCounts(BaseModel):
    new: int
    fixed: int
    persistent: int
    not_retested: int


class Comparison(BaseModel):
    model_config = example(ex.COMPARISON)
    old_run_id: uuid.UUID
    new_run_id: uuid.UUID
    warnings: list[str] = Field(description="scope_differs, profile_differs, policy_versions_differ, incomplete_runs.")
    new: list[FindingGroup]
    fixed: list[FindingGroup] = Field(description="Gone AND the endpoint was tested again in the newer run.")
    persistent: list[FindingGroup]
    not_retested: list[FindingGroup] = Field(description="Endpoint not tested in the newer run: unknown, never counted as fixed.")
    endpoints_added: list[str]
    endpoints_removed: list[str]
    endpoint_changes: list[EndpointChange]
    counts: ComparisonCounts


class ErrorBody(BaseModel):
    detail: str
