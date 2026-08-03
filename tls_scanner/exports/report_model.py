"""
Common report model and aggregation logic.

Called by:
- report renderers and export orchestration after a scan is complete.

Produces:
- one scan-level source of truth for endpoints, statistics, findings, policy status,
  and observations used by HTML, Markdown, CSV findings, metadata, and CBOM exports.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib import metadata
from typing import Any

from ..constants import PQC_TLS_GROUPS
from ..crypto_policy import selected_policies
from ..models import EncryptionPolicy, ScanJob


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}
GRADE_ORDER = {"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "F": 5, "Not Tested": 6}
TLS_VERSIONS = ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")


@dataclass(frozen=True)
class ScanMetadata:
    report_name: str
    scan_timestamp: str
    scan_run_id: str
    scanner_version: str
    scan_duration_seconds: float | None
    targets: str
    ports: str
    crypto_profile: str
    dns_resolution: str
    policy_mode: str
    frequency: str
    target_groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicySummary:
    policy_id: str
    name: str
    version: str
    description: str
    compliance_percentage: int
    compliant_endpoints: int
    non_compliant_endpoints: int
    failed_controls: int


@dataclass(frozen=True)
class CipherSuiteObservation:
    tls_version: str
    name: str
    key_exchange: str
    authentication: str
    encryption: str
    hash_algorithm: str
    forward_secrecy: str
    strength: str
    compliance_status: str
    policy_reason: str


@dataclass(frozen=True)
class CertificateObservation:
    subject: str
    issuer: str
    san: tuple[str, ...]
    serial_number: str
    valid_from: str
    valid_until: str
    remaining_days: int | None
    self_signed: str
    key_type: str
    key_size: int | None
    signature_algorithm: str
    fingerprint: str
    trust_status: str
    hostname_validation_status: str
    san_validation_status: str
    chain_validation_status: str
    revocation_status: str
    ocsp_status: str
    crl_status: str
    status: str


@dataclass(frozen=True)
class FindingOccurrence:
    finding_id: str
    endpoint_id: str
    evidence: str
    status: str
    policy_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    category: str
    severity: str
    status: str
    description: str
    technical_impact: str
    evidence: str
    remediation: str
    affected_endpoint_ids: tuple[str, ...]
    policy_ids: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    first_detected: str = ""
    last_observed: str = ""


@dataclass(frozen=True)
class EndpointReport:
    endpoint_id: str
    host_id: str
    hostname: str
    ip_address: str
    port: str
    protocol: str
    overall_grade: str
    compliance_status: str
    highest_severity: str
    finding_ids: tuple[str, ...]
    finding_count: int
    tls_versions: dict[str, str]
    supported_tls_versions: tuple[str, ...]
    cipher_suites: tuple[CipherSuiteObservation, ...]
    certificate: CertificateObservation
    pki: dict[str, str]
    pqc: dict[str, Any]
    security_breakdown: dict[str, str]
    technical_rows: tuple[tuple[Any, ...], ...]
    errors: tuple[str, ...] = ()
    untested_checks: tuple[str, ...] = ()


@dataclass(frozen=True)
class HostReport:
    host_id: str
    hostname: str
    ip_address: str
    endpoint_ids: tuple[str, ...]


@dataclass(frozen=True)
class ReportStatistics:
    total_hosts: int
    total_endpoints: int
    compliant_endpoints: int
    non_compliant_endpoints: int
    endpoints_with_errors: int
    endpoints_not_fully_tested: int
    unique_findings: int
    finding_occurrences: int
    critical_findings: int
    high_findings: int
    expired_certificates: int
    certificates_expiring_soon: int
    checks_not_tested: int
    overall_grade: str
    compliance_status: str
    grade_distribution: dict[str, int]
    endpoint_compliance: dict[str, int]
    findings_by_severity: dict[str, dict[str, int]]
    top_findings: list[dict[str, Any]]
    tls_version_distribution: dict[str, int]
    certificate_status: dict[str, int]
    certificate_expiration_timeline: dict[str, int]
    pqc_readiness: dict[str, int]


@dataclass(frozen=True)
class ReportModel:
    metadata: ScanMetadata
    statistics: ReportStatistics
    hosts: tuple[HostReport, ...]
    endpoints: tuple[EndpointReport, ...]
    findings: tuple[Finding, ...]
    finding_occurrences: tuple[FindingOccurrence, ...]
    policies: tuple[PolicySummary, ...]
    raw_results: tuple[tuple[Any, ...], ...]
    errors: tuple[str, ...] = ()


def stable_endpoint_id(ip_address: Any, port: Any, protocol: str = "tcp") -> str:
    return f"{ip_address}:{port}/{protocol}"


def safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_tls_version(value: Any) -> str:
    mapped = {
        "SSLv2": "SSL 2.0",
        "SSLv3": "SSL 3.0",
        "TLSv1.0": "TLS 1.0",
        "TLSv1.1": "TLS 1.1",
        "TLSv1.2": "TLS 1.2",
        "TLSv1.3": "TLS 1.3",
    }
    return mapped.get(str(value), str(value) if value else "Not Tested")


def endpoint_status(rows: list[list[Any]]) -> str:
    if not rows:
        return "not_tested"
    statuses = {str(row[-2]).upper() for row in rows if len(row) >= 2}
    if "ERROR" in statuses:
        return "error"
    if "KO" in statuses:
        return "non_compliant"
    if "OK" in statuses:
        return "compliant"
    return "not_tested"


def parse_cipher_suite(cipher_suite: Any) -> dict[str, str]:
    name = str(cipher_suite or "")
    tokens = name.upper().split("_")
    key_exchange = "TLS 1.3" if name.startswith("TLS_AES") or name.startswith("TLS_CHACHA") else "Unknown"
    authentication = "Unknown"
    if "RSA" in tokens:
        authentication = "RSA"
        key_exchange = "RSA" if key_exchange == "Unknown" else key_exchange
    if "ECDHE" in tokens:
        key_exchange = "ECDHE"
    if "DHE" in tokens and "ECDHE" not in tokens:
        key_exchange = "DHE"
    if "ECDSA" in tokens:
        authentication = "ECDSA"
    encryption = "Unknown"
    for marker in ("CHACHA20", "AES_256_GCM", "AES_128_GCM", "AES_256_CBC", "AES_128_CBC", "3DES", "DES", "RC4", "NULL"):
        if marker in name.upper():
            encryption = marker.replace("_", " ")
            break
    hash_algorithm = "AEAD"
    for marker in ("SHA384", "SHA256", "SHA1", "SHA", "MD5"):
        if marker in tokens or name.upper().endswith(marker):
            hash_algorithm = "SHA-1" if marker in {"SHA", "SHA1"} else marker.replace("SHA", "SHA-")
            break
    forward_secrecy = "Yes" if key_exchange in {"ECDHE", "DHE"} or name.startswith("TLS_AES") or name.startswith("TLS_CHACHA") else "No"
    weak_tokens = {"NULL", "EXPORT", "RC4", "DES", "3DES", "MD5"}
    strength = "Weak" if weak_tokens.intersection(tokens) else "Modern" if hash_algorithm == "AEAD" else "Legacy"
    return {
        "key_exchange": key_exchange,
        "authentication": authentication,
        "encryption": encryption,
        "hash_algorithm": hash_algorithm,
        "forward_secrecy": forward_secrecy,
        "strength": strength,
    }


def row_indexes(row: list[Any], crypto: str) -> dict[str, int]:
    if len(row) >= 19:
        return {
            "ip": 0, "fqdn": 1, "port": 2, "grade": 3, "tls": 4, "cipher": 5,
            "public_key": 6, "cert_validity": 7, "key_exchange": 8 if crypto == "pqc" else -1,
            "cert_crypto": 8 if crypto != "pqc" else 9, "self_signed": 9 if crypto != "pqc" else 10,
            "days_left": 10 if crypto != "pqc" else 11, "issuer": 11 if crypto != "pqc" else 12,
            "subject": 12 if crypto != "pqc" else 13, "san": 13 if crypto != "pqc" else 14,
            "key_type": 14 if crypto != "pqc" else 15, "key_size": 15 if crypto != "pqc" else 16,
            "signature": 16 if crypto != "pqc" else 17, "compliance": -2, "reason": -1,
        }
    return {
        "ip": 0, "fqdn": 1, "port": 2, "grade": 3, "tls": 4, "cipher": 5,
        "public_key": 6, "cert_validity": 7, "key_exchange": 8 if crypto == "pqc" and len(row) > 10 else -1,
        "cert_crypto": -7, "self_signed": -6, "days_left": -5, "issuer": -4,
        "subject": -3, "san": -2, "key_type": -1, "key_size": -1,
        "signature": -1, "compliance": -2, "reason": -1,
    }


def row_value(row: list[Any], indexes: dict[str, int], name: str, default: Any = "") -> Any:
    index = indexes[name]
    if index < 0:
        index = len(row) + index
    if 0 <= index < len(row):
        return row[index]
    return default


FINDING_DEFINITIONS = {
    "TLS_DEPRECATED_VERSION": (
        "Deprecated TLS Version Enabled", "TLS Versions", "high",
        "The endpoint accepts a TLS protocol version that is no longer recommended.",
        "Deprecated TLS versions expose sessions to protocol downgrade and legacy cryptographic weaknesses.",
        "Disable TLS 1.0 and TLS 1.1. Prefer TLS 1.3 and keep TLS 1.2 only with modern cipher suites.",
    ),
    "TLS_WEAK_CIPHER_SUITE": (
        "Weak Cipher Suite Accepted", "Cipher Suites", "medium",
        "The endpoint accepts at least one cipher suite that does not match the selected policy.",
        "Weak cipher suites can reduce confidentiality or integrity guarantees for negotiated sessions.",
        "Disable weak and legacy cipher suites. Prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
    ),
    "TLS_NO_FORWARD_SECRECY": (
        "Forward Secrecy Not Offered", "Cipher Suites", "medium",
        "The endpoint accepts a cipher suite without forward secrecy.",
        "Compromise of a long-term private key may expose previously captured traffic.",
        "Enable ECDHE or TLS 1.3 cipher suites and disable static RSA key exchange.",
    ),
    "CERTIFICATE_EXPIRED": (
        "Certificate Expired", "Certificate", "high",
        "The endpoint presented an expired certificate.",
        "Clients may reject the service or users may bypass security warnings.",
        "Renew and deploy a valid certificate from the appropriate certificate authority.",
    ),
    "CERTIFICATE_EXPIRING_SOON": (
        "Certificate Expiring Soon", "Certificate", "medium",
        "The endpoint certificate is approaching expiration.",
        "Service availability and trust may be affected if the certificate is not renewed in time.",
        "Plan renewal and deployment before the certificate expires.",
    ),
    "CERTIFICATE_SELF_SIGNED": (
        "Self-Signed Certificate", "Certificate", "medium",
        "The endpoint presented a self-signed certificate.",
        "Clients cannot establish trust through a recognized certificate chain.",
        "Use a certificate issued by a trusted internal or public certificate authority.",
    ),
    "CERTIFICATE_WEAK_SIGNATURE": (
        "Weak Certificate Signature", "Certificate", "medium",
        "The certificate uses a weak signature algorithm.",
        "Weak signatures reduce confidence in certificate integrity and chain validation.",
        "Replace the certificate with one signed using SHA-256 or stronger.",
    ),
    "CERTIFICATE_RSA_KEY_TOO_SMALL": (
        "RSA Certificate Key Too Small", "Certificate", "high",
        "The certificate RSA key is smaller than the selected policy minimum.",
        "Small RSA keys may be vulnerable to practical cryptographic attacks.",
        "Replace the certificate with an RSA key of at least the selected policy minimum.",
    ),
    "PQC_HYBRID_GROUP_NOT_SUPPORTED": (
        "Hybrid ML-KEM Group Not Supported", "PQC Readiness", "informational",
        "The endpoint did not negotiate a supported hybrid ML-KEM TLS group during the PQC scan.",
        "The endpoint currently relies on classical key exchange for the observed handshake.",
        "Track vendor support and test hybrid groups in a controlled rollout.",
    ),
    "SCAN_ERROR": (
        "Endpoint Scan Error", "Scan Reliability", "low",
        "The endpoint could not be fully tested.",
        "Security posture may be incomplete for this endpoint.",
        "Review scanner connectivity, firewall rules, and service availability.",
    ),
}


def classify_finding(reason: Any, tls_version: Any = "", cipher_suite: Any = "") -> str:
    normalized = f"{reason} {tls_version} {cipher_suite}".casefold()
    if "error" in normalized:
        return "SCAN_ERROR"
    if "tls 1.0" in normalized or "tls 1.1" in normalized or "tlsv1.0" in normalized or "tlsv1.1" in normalized or "tls version" in normalized:
        return "TLS_DEPRECATED_VERSION"
    if "no supported pqc" in normalized or "pqc" in normalized:
        return "PQC_HYBRID_GROUP_NOT_SUPPORTED"
    if "forward secrecy" in normalized or "tls_rsa_" in normalized:
        return "TLS_NO_FORWARD_SECRECY"
    if "certificate expired" in normalized:
        return "CERTIFICATE_EXPIRED"
    if "rsa key" in normalized:
        return "CERTIFICATE_RSA_KEY_TOO_SMALL"
    if "sha-1" in normalized or "sha1" in normalized or "signature hash" in normalized:
        return "CERTIFICATE_WEAK_SIGNATURE"
    if "cipher" in normalized:
        return "TLS_WEAK_CIPHER_SUITE"
    return "TLS_WEAK_CIPHER_SUITE"


def build_certificate(row: list[Any], indexes: dict[str, int], expires_within_days: int) -> CertificateObservation:
    days_left = safe_int(row_value(row, indexes, "days_left", None))
    self_signed = str(row_value(row, indexes, "self_signed", "unknown") or "unknown")
    key_size = safe_int(row_value(row, indexes, "key_size", None))
    signature_algorithm = str(row_value(row, indexes, "signature", "unknown") or "unknown")
    cert_validity = str(row_value(row, indexes, "cert_validity", "N/A") or "N/A")
    key_type = str(row_value(row, indexes, "key_type", "Unknown") or "Unknown")
    san = tuple(
        item.strip()
        for item in str(row_value(row, indexes, "san", "-") or "-").split(",")
        if item.strip() and item.strip() != "-"
    )
    normalized_signature = signature_algorithm.upper().replace("-", "").replace("_", "")
    status = "Valid"
    if cert_validity == "N/A":
        status = "Validation not tested"
    elif days_left is not None and days_left < 0:
        status = "Expired"
    elif days_left is not None and days_left <= expires_within_days:
        status = "Expiring soon"
    if self_signed == "yes":
        status = "Self-signed"
    if key_type.upper() == "RSA" and key_size is not None and key_size < 2048:
        status = "Weak key"
    if "SHA1" in normalized_signature or normalized_signature.endswith("SHA") or "MD5" in normalized_signature:
        status = "Weak signature"
    return CertificateObservation(
        subject=str(row_value(row, indexes, "subject", "-") or "-"),
        issuer=str(row_value(row, indexes, "issuer", "-") or "-"),
        san=san,
        serial_number="Not Tested",
        valid_from="Not Tested",
        valid_until=cert_validity,
        remaining_days=days_left,
        self_signed=self_signed,
        key_type=key_type,
        key_size=key_size,
        signature_algorithm=signature_algorithm,
        fingerprint="Not Tested",
        trust_status="Not Tested",
        hostname_validation_status="Not Tested",
        san_validation_status="Not Tested",
        chain_validation_status="Not Tested",
        revocation_status="Not Tested",
        ocsp_status="Not Tested",
        crl_status="Not Tested",
        status=status,
    )


def add_finding(
    grouped: dict[str, dict[str, Any]],
    occurrences: list[FindingOccurrence],
    finding_id: str,
    endpoint_id: str,
    evidence: str,
    status: str,
    policy_ids: tuple[str, ...],
    scan_timestamp: str,
) -> None:
    title, category, severity, description, impact, remediation = FINDING_DEFINITIONS[finding_id]
    item = grouped.setdefault(
        finding_id,
        {
            "finding_id": finding_id,
            "title": title,
            "category": category,
            "severity": severity,
            "status": status,
            "description": description,
            "technical_impact": impact,
            "evidence": set(),
            "remediation": remediation,
            "affected_endpoint_ids": set(),
            "policy_ids": set(),
            "references": (),
            "first_detected": scan_timestamp,
            "last_observed": scan_timestamp,
        },
    )
    item["affected_endpoint_ids"].add(endpoint_id)
    item["policy_ids"].update(policy_ids)
    if evidence:
        item["evidence"].add(str(evidence))
    occurrences.append(FindingOccurrence(finding_id, endpoint_id, str(evidence), status, policy_ids))


def package_version() -> str:
    try:
        return metadata.version("tls-scanner")
    except metadata.PackageNotFoundError:
        return "local"


def build_report_model(
    results: list[list[Any]],
    job: ScanJob,
    scan_timestamp: str,
    scan_duration_seconds: float | None = None,
) -> ReportModel:
    policy_objects: tuple[EncryptionPolicy, ...] = selected_policies(job.policies)
    policy_ids = tuple(policy.name for policy in policy_objects)
    rows_by_endpoint: dict[str, list[list[Any]]] = {}
    for row in results:
        if len(row) < 8:
            continue
        endpoint_id = stable_endpoint_id(row[0], row[2])
        rows_by_endpoint.setdefault(endpoint_id, []).append(row)

    grouped_findings: dict[str, dict[str, Any]] = {}
    occurrences: list[FindingOccurrence] = []
    endpoints: list[EndpointReport] = []
    hosts: dict[str, HostReport] = {}

    for endpoint_id, endpoint_rows in sorted(rows_by_endpoint.items()):
        first = endpoint_rows[0]
        indexes = row_indexes(first, job.crypto)
        ip_address = str(row_value(first, indexes, "ip", "-"))
        hostname = str(row_value(first, indexes, "fqdn", "") or ip_address)
        port = str(row_value(first, indexes, "port", "-"))
        host_id = hostname or ip_address
        compliance = endpoint_status(endpoint_rows)
        grade = str(row_value(first, indexes, "grade", "Not Tested") or "Not Tested")
        supported_versions = sorted(
            {normalize_tls_version(row_value(row, row_indexes(row, job.crypto), "tls")) for row in endpoint_rows}
        )
        tls_versions = {version: "unsupported" for version in TLS_VERSIONS}
        for version in supported_versions:
            if version in tls_versions:
                tls_versions[version] = "non-compliant" if version in {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"} else "supported"
        certificate = build_certificate(first, indexes, job.certificate_expires_within_days)
        cipher_suites = []
        endpoint_finding_ids: set[str] = set()
        untested_checks = ["Trust chain validation", "Hostname validation", "SAN validation", "Revocation status", "OCSP status", "CRL status"]
        errors = []
        for row in endpoint_rows:
            idx = row_indexes(row, job.crypto)
            tls = normalize_tls_version(row_value(row, idx, "tls"))
            cipher = str(row_value(row, idx, "cipher", "-") or "-")
            reason = str(row_value(row, idx, "reason", "") or "")
            row_compliance = str(row_value(row, idx, "compliance", "") or "")
            parsed = parse_cipher_suite(cipher)
            cipher_suites.append(
                CipherSuiteObservation(
                    tls_version=tls,
                    name=cipher,
                    key_exchange=str(row_value(row, idx, "key_exchange", "") or parsed["key_exchange"]),
                    authentication=parsed["authentication"],
                    encryption=parsed["encryption"],
                    hash_algorithm=parsed["hash_algorithm"],
                    forward_secrecy=parsed["forward_secrecy"],
                    strength=parsed["strength"],
                    compliance_status="compliant" if row_compliance.upper() == "OK" else "non_compliant",
                    policy_reason=reason,
                )
            )
            if row_compliance.upper() in {"KO", "ERROR"}:
                finding_id = classify_finding(reason, tls, cipher)
                endpoint_finding_ids.add(finding_id)
                if row_compliance.upper() == "ERROR":
                    errors.append(reason or "Scan error")
                add_finding(grouped_findings, occurrences, finding_id, endpoint_id, reason or cipher, row_compliance, policy_ids, scan_timestamp)
            if parsed["forward_secrecy"] == "No" and cipher.startswith("TLS_RSA_"):
                finding_id = "TLS_NO_FORWARD_SECRECY"
                endpoint_finding_ids.add(finding_id)
                add_finding(grouped_findings, occurrences, finding_id, endpoint_id, cipher, "WARNING", policy_ids, scan_timestamp)

        if certificate.remaining_days is not None:
            if certificate.remaining_days < 0:
                endpoint_finding_ids.add("CERTIFICATE_EXPIRED")
                add_finding(grouped_findings, occurrences, "CERTIFICATE_EXPIRED", endpoint_id, f"Certificate expired on {certificate.valid_until}", "KO", policy_ids, scan_timestamp)
            elif certificate.remaining_days <= job.certificate_expires_within_days:
                endpoint_finding_ids.add("CERTIFICATE_EXPIRING_SOON")
                add_finding(grouped_findings, occurrences, "CERTIFICATE_EXPIRING_SOON", endpoint_id, f"Certificate expires in {certificate.remaining_days} day(s)", "WARNING", policy_ids, scan_timestamp)
        if certificate.self_signed == "yes":
            endpoint_finding_ids.add("CERTIFICATE_SELF_SIGNED")
            add_finding(grouped_findings, occurrences, "CERTIFICATE_SELF_SIGNED", endpoint_id, certificate.subject, "KO", policy_ids, scan_timestamp)
        if certificate.key_type.upper() == "RSA" and certificate.key_size is not None and certificate.key_size < 2048:
            endpoint_finding_ids.add("CERTIFICATE_RSA_KEY_TOO_SMALL")
            add_finding(grouped_findings, occurrences, "CERTIFICATE_RSA_KEY_TOO_SMALL", endpoint_id, f"RSA {certificate.key_size}-bit key", "KO", policy_ids, scan_timestamp)
        normalized_signature = certificate.signature_algorithm.upper().replace("-", "").replace("_", "")
        if "SHA1" in normalized_signature or normalized_signature.endswith("SHA") or "MD5" in normalized_signature:
            endpoint_finding_ids.add("CERTIFICATE_WEAK_SIGNATURE")
            add_finding(grouped_findings, occurrences, "CERTIFICATE_WEAK_SIGNATURE", endpoint_id, certificate.signature_algorithm, "KO", policy_ids, scan_timestamp)

        pqc_group = next((suite.key_exchange for suite in cipher_suites if suite.key_exchange in PQC_TLS_GROUPS), "")
        pqc_status = "Supports hybrid ML-KEM" if pqc_group else "Classical cryptography only"
        if job.crypto != "pqc":
            pqc_status = "Not Tested"
        elif not pqc_group:
            endpoint_finding_ids.add("PQC_HYBRID_GROUP_NOT_SUPPORTED")
            add_finding(grouped_findings, occurrences, "PQC_HYBRID_GROUP_NOT_SUPPORTED", endpoint_id, "No supported PQC group", "INFO", policy_ids, scan_timestamp)
        severities = [grouped_findings[finding_id]["severity"] for finding_id in endpoint_finding_ids]
        highest_severity = min(severities, key=SEVERITY_ORDER.get) if severities else "none"
        security_breakdown = {
            "TLS Versions": "Needs Attention" if any(version in {"TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0"} for version in supported_versions) else "Pass",
            "Cipher Suites": "Needs Attention" if any(suite.compliance_status == "non_compliant" for suite in cipher_suites) else "Pass",
            "Certificate": certificate.status,
            "PKI": "Not Tested",
            "Protocol Security": "Needs Attention" if any(suite.forward_secrecy == "No" for suite in cipher_suites) else "Pass",
            "PQC Readiness": pqc_status,
        }
        endpoint = EndpointReport(
            endpoint_id=endpoint_id,
            host_id=host_id,
            hostname=hostname,
            ip_address=ip_address,
            port=port,
            protocol="tcp",
            overall_grade=grade,
            compliance_status=compliance,
            highest_severity=highest_severity,
            finding_ids=tuple(sorted(endpoint_finding_ids, key=lambda item: (SEVERITY_ORDER.get(grouped_findings[item]["severity"], 9), item))),
            finding_count=len(endpoint_finding_ids),
            tls_versions=tls_versions,
            supported_tls_versions=tuple(supported_versions),
            cipher_suites=tuple(cipher_suites),
            certificate=certificate,
            pki={
                "Trust chain validation": "Not Tested",
                "Hostname validation": "Not Tested",
                "SAN validation": "Not Tested",
                "Certificate chain status": "Not Tested",
                "Revocation status": "Not Tested",
                "OCSP status": "Not Tested",
                "CRL status": "Not Tested",
            },
            pqc={
                "readiness": pqc_status,
                "supported_hybrid_groups": tuple(sorted({suite.key_exchange for suite in cipher_suites if suite.key_exchange in PQC_TLS_GROUPS})),
                "ml_kem_support": "Yes" if pqc_group else "No",
                "scan_status": "tested" if job.crypto == "pqc" else "not_tested",
            },
            security_breakdown=security_breakdown,
            technical_rows=tuple(tuple(row) for row in endpoint_rows),
            errors=tuple(errors),
            untested_checks=tuple(untested_checks),
        )
        endpoints.append(endpoint)
        existing_host = hosts.get(host_id)
        endpoint_ids = tuple(sorted(set((existing_host.endpoint_ids if existing_host else ()) + (endpoint_id,))))
        hosts[host_id] = HostReport(host_id, hostname, ip_address, endpoint_ids)

    findings = tuple(
        Finding(
            finding_id=item["finding_id"],
            title=item["title"],
            category=item["category"],
            severity=item["severity"],
            status=item["status"],
            description=item["description"],
            technical_impact=item["technical_impact"],
            evidence="; ".join(sorted(item["evidence"])) or "Observed during scan.",
            remediation=item["remediation"],
            affected_endpoint_ids=tuple(sorted(item["affected_endpoint_ids"])),
            policy_ids=tuple(sorted(item["policy_ids"])),
            references=item["references"],
            first_detected=item["first_detected"],
            last_observed=item["last_observed"],
        )
        for item in sorted(grouped_findings.values(), key=lambda value: (SEVERITY_ORDER.get(value["severity"], 9), value["finding_id"]))
    )

    stats = build_statistics(endpoints, findings, occurrences, policy_objects)
    policies = tuple(
        PolicySummary(
            policy_id=policy.name,
            name=policy.name,
            version=policy.version,
            description=policy.description,
            compliance_percentage=stats.compliant_endpoints * 100 // stats.total_endpoints if stats.total_endpoints else 0,
            compliant_endpoints=stats.compliant_endpoints,
            non_compliant_endpoints=stats.non_compliant_endpoints,
            failed_controls=stats.finding_occurrences,
        )
        for policy in policy_objects
    )
    metadata_model = ScanMetadata(
        report_name=job.report_name,
        scan_timestamp=scan_timestamp,
        scan_run_id=job.scan_run_id,
        scanner_version=package_version(),
        scan_duration_seconds=scan_duration_seconds,
        targets=job.targets,
        ports=str(job.ports),
        crypto_profile=job.crypto,
        dns_resolution="disabled" if job.ip else "enabled",
        policy_mode=job.policy_mode,
        frequency=job.frequency,
        target_groups=tuple(group.name for group in job.target_groups),
    )
    return ReportModel(
        metadata=metadata_model,
        statistics=stats,
        hosts=tuple(sorted(hosts.values(), key=lambda host: host.host_id)),
        endpoints=tuple(endpoints),
        findings=findings,
        finding_occurrences=tuple(occurrences),
        policies=policies,
        raw_results=tuple(tuple(row) for row in results),
    )


def build_statistics(
    endpoints: list[EndpointReport],
    findings: tuple[Finding, ...],
    occurrences: list[FindingOccurrence],
    policies: tuple[EncryptionPolicy, ...],
) -> ReportStatistics:
    total_endpoints = len(endpoints)
    total_hosts = len({endpoint.host_id for endpoint in endpoints})
    compliant = sum(1 for endpoint in endpoints if endpoint.compliance_status == "compliant")
    non_compliant = sum(1 for endpoint in endpoints if endpoint.compliance_status == "non_compliant")
    with_errors = sum(1 for endpoint in endpoints if endpoint.compliance_status == "error" or endpoint.errors)
    not_tested = sum(1 for endpoint in endpoints if endpoint.compliance_status == "not_tested")
    grade_distribution = {grade: 0 for grade in ("A+", "A", "B", "C", "D", "F")}
    for endpoint in endpoints:
        if endpoint.overall_grade in grade_distribution:
            grade_distribution[endpoint.overall_grade] += 1
    endpoint_compliance = {
        "Compliant endpoints": compliant,
        "Non-compliant endpoints": non_compliant,
        "Endpoints with errors": with_errors,
        "Endpoints not fully tested": not_tested,
    }
    severity_counts = {label: {"unique": 0, "occurrences": 0} for label in ("critical", "high", "medium", "low", "informational")}
    for finding in findings:
        severity_counts[finding.severity]["unique"] += 1
    for occurrence in occurrences:
        severity = next((finding.severity for finding in findings if finding.finding_id == occurrence.finding_id), "informational")
        severity_counts[severity]["occurrences"] += 1
    top_findings = [
        {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "affected_endpoints": len(finding.affected_endpoint_ids),
            "severity": finding.severity,
        }
        for finding in sorted(findings, key=lambda item: (-len(item.affected_endpoint_ids), SEVERITY_ORDER.get(item.severity, 9), item.title))[:10]
    ]
    tls_distribution = {version: 0 for version in TLS_VERSIONS}
    for endpoint in endpoints:
        for version in endpoint.supported_tls_versions:
            if version in tls_distribution:
                tls_distribution[version] += 1
    certificate_status = {
        "Valid": 0,
        "Expiring soon": 0,
        "Expired": 0,
        "Self-signed": 0,
        "Weak key": 0,
        "Weak signature": 0,
        "Validation not tested": 0,
    }
    expiration_timeline = {
        "Already expired": 0,
        "Within 7 days": 0,
        "Within 30 days": 0,
        "Within 60 days": 0,
        "Within 90 days": 0,
        "After 90 days": 0,
    }
    for endpoint in endpoints:
        certificate_status[endpoint.certificate.status] = certificate_status.get(endpoint.certificate.status, 0) + 1
        days = endpoint.certificate.remaining_days
        if days is None:
            continue
        if days < 0:
            expiration_timeline["Already expired"] += 1
        elif days <= 7:
            expiration_timeline["Within 7 days"] += 1
        elif days <= 30:
            expiration_timeline["Within 30 days"] += 1
        elif days <= 60:
            expiration_timeline["Within 60 days"] += 1
        elif days <= 90:
            expiration_timeline["Within 90 days"] += 1
        else:
            expiration_timeline["After 90 days"] += 1
    pqc = {
        "Endpoints supporting hybrid ML-KEM groups": sum(1 for endpoint in endpoints if endpoint.pqc["readiness"] == "Supports hybrid ML-KEM"),
        "Classical cryptography only": sum(1 for endpoint in endpoints if endpoint.pqc["readiness"] == "Classical cryptography only"),
        "Endpoints not tested for PQC": sum(1 for endpoint in endpoints if endpoint.pqc["readiness"] == "Not Tested"),
        "Endpoints with PQC scan errors": sum(1 for endpoint in endpoints if endpoint.pqc.get("scan_status") == "error"),
    }
    # Metrics are endpoint based: one endpoint contributes at most once to grade and compliance KPIs.
    overall_grade = max((endpoint.overall_grade for endpoint in endpoints), key=lambda grade: GRADE_ORDER.get(grade, 99), default="Not Tested")
    compliance_status = "Compliant" if total_endpoints and compliant == total_endpoints else "Non-compliant" if non_compliant else "Not Fully Tested"
    return ReportStatistics(
        total_hosts=total_hosts,
        total_endpoints=total_endpoints,
        compliant_endpoints=compliant,
        non_compliant_endpoints=non_compliant,
        endpoints_with_errors=with_errors,
        endpoints_not_fully_tested=not_tested,
        unique_findings=len(findings),
        finding_occurrences=len(occurrences),
        critical_findings=sum(1 for finding in findings if finding.severity == "critical"),
        high_findings=sum(1 for finding in findings if finding.severity == "high"),
        expired_certificates=certificate_status.get("Expired", 0),
        certificates_expiring_soon=certificate_status.get("Expiring soon", 0),
        checks_not_tested=sum(len(endpoint.untested_checks) for endpoint in endpoints),
        overall_grade=overall_grade,
        compliance_status=compliance_status,
        grade_distribution=grade_distribution,
        endpoint_compliance=endpoint_compliance,
        findings_by_severity=severity_counts,
        top_findings=top_findings,
        tls_version_distribution=tls_distribution,
        certificate_status=certificate_status,
        certificate_expiration_timeline=expiration_timeline,
        pqc_readiness=pqc,
    )


def report_model_to_dict(model: ReportModel) -> dict[str, Any]:
    return asdict(model)


def build_metadata_document(model: ReportModel, basename: str, written_files: list[str]) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "basename": basename,
        "metadata": asdict(model.metadata),
        "statistics": asdict(model.statistics),
        "files": written_files,
    }
