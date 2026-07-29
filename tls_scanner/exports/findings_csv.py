"""
Security findings CSV export builder.
"""

from .markdown_report import build_security_findings


def build_findings_csv_export(results, include_certificate_findings=True, expires_within_days=30):
    headers = [
        "Severity",
        "Status",
        "IP",
        "FQDN",
        "Port",
        "Check",
        "Evidence",
        "Remediation",
    ]
    rows = [
        [
            finding.severity,
            finding.status,
            finding.ip,
            finding.fqdn,
            finding.port,
            finding.check,
            finding.evidence,
            finding.remediation,
        ]
        for finding in build_security_findings(
            results,
            include_certificate_findings=include_certificate_findings,
            expires_within_days=expires_within_days,
        )
    ]
    return headers, rows
