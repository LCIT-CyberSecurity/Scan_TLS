"""
Security findings CSV export builder.
"""

from .report_model import build_report_model


def build_findings_csv_export_from_model(model):
    headers = [
        "Finding ID",
        "Severity",
        "Status",
        "Category",
        "Title",
        "Affected Endpoint Count",
        "Affected Endpoints",
        "Evidence",
        "Technical Impact",
        "Remediation",
        "Policies",
        "References",
    ]
    rows = [
        [
            finding.finding_id,
            finding.severity,
            finding.status,
            finding.category,
            finding.title,
            len(finding.affected_endpoint_ids),
            ", ".join(finding.affected_endpoint_ids),
            finding.evidence,
            finding.technical_impact,
            finding.remediation,
            ", ".join(finding.policy_ids),
            ", ".join(finding.references),
        ]
        for finding in model.findings
    ]
    return headers, rows


def build_findings_csv_export(results, include_certificate_findings=True, expires_within_days=30):
    from ..models import ScanJob

    job = ScanJob(targets="", ports="", crypto="standard", ip=False)
    job.certificate_findings_enabled = include_certificate_findings
    job.certificate_expires_within_days = expires_within_days
    return build_findings_csv_export_from_model(build_report_model(results, job, ""))
