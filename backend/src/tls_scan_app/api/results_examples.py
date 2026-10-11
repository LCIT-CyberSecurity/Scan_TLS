"""Representative JSON examples shown in Swagger for the results API."""
RUN_ID = "3f0c1d52-8b7e-4a8e-9a57-2f1c6f0b9a11"
DEF_ID = "a1b2c3d4-0000-4000-8000-000000000001"
SUMMARY = {
    "total_hosts": 2, "total_endpoints": 3, "compliant_endpoints": 2, "non_compliant_endpoints": 1, "endpoints_with_errors": 0,
    "endpoints_not_fully_tested": 0, "unique_findings": 2, "finding_occurrences": 2,
    "findings_by_severity": {"critical": {"unique": 0, "occurrences": 0}, "high": {"unique": 1, "occurrences": 1},
                             "medium": {"unique": 1, "occurrences": 1}, "low": {"unique": 0, "occurrences": 0},
                             "informational": {"unique": 0, "occurrences": 0}},
    "checks_not_tested": 6, "overall_grade": "C", "compliance_status": "Non-compliant",
}
RUN = {
    "id": RUN_ID, "name": "Weekly external perimeter", "status": "completed", "phase": "done",
    "definition": {"id": DEF_ID, "name": "External perimeter"}, "initiated_by": "7d6f1e0a-1111-4222-8333-444455556666",
    "queued_at": "2026-05-04T06:00:00Z", "started_at": "2026-05-04T06:00:03Z", "finished_at": "2026-05-04T06:02:41Z",
    "duration_seconds": 158.2, "tags": ["prod"], "information_systems": ["0b9d1c52-2222-4333-8444-555566667777"], "summary": SUMMARY,
}
REPORT = {"format": "html", "size": 482113, "sha256": "9f2c...e41a", "content_type": "text/html", "available": True,
          "download_url": f"/api/results/{RUN_ID}/reports/html"}
RUN_DETAIL = RUN | {
    "profile": {"id": "5c5c5c5c-0000-4000-8000-000000000002", "name": "Standard"}, "profile_version": 3,
    "policy_versions": [{"name": "ANSSI", "version": 2, "version_id": "6d6d6d6d-0000-4000-8000-000000000003"}],
    "progress": None, "error": None, "endpoint_errors": {}, "untested_checks": {"10.0.0.5:443/tcp": ["Revocation status"]},
    "skipped_hosts": [], "reports": [REPORT],
}
CERT = {"subject": "CN=www.example.org", "issuer": "CN=Example CA", "valid_until": "2026-11-01T00:00:00+00:00", "remaining_days": 181,
        "key_type": "RSA", "key_size": 2048, "signature_algorithm": "sha256WithRSAEncryption", "fingerprint": "AB:CD:...",
        "trust_status": "trusted", "chain_validation_status": "valid", "revocation_status": None, "self_signed": False, "status": "Valid"}
ENDPOINT = {"endpoint_id": "10.0.0.5:443/tcp", "hostname": "www.example.org", "ip_address": "10.0.0.5", "port": 443, "grade": "B",
            "compliance_status": "non_compliant", "highest_severity": "high", "tls_versions": ["TLSv1.2", "TLSv1.3"],
            "cipher_suites": ["TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES128-SHA"], "certificate": CERT, "errors": [],
            "untested_checks": ["Revocation status"], "tags": ["prod"]}
FINDING = {"finding_id": "TLS_LEGACY_CIPHER", "title": "Legacy cipher suite accepted", "category": "Cipher suites", "severity": "high",
           "status": "open", "evidence": "ECDHE-RSA-AES128-SHA accepted on 10.0.0.5:443", "remediation": "Disable CBC cipher suites.",
           "affected_endpoint_ids": ["10.0.0.5:443/tcp"]}
GROUP = {"finding_id": "TLS_LEGACY_CIPHER", "title": "Legacy cipher suite accepted", "severity": "high", "affected": ["10.0.0.5:443/tcp"]}
COMPARISON = {
    "old_run_id": "11111111-2222-4333-8444-555555555555", "new_run_id": RUN_ID, "warnings": [],
    "new": [GROUP], "fixed": [], "persistent": [], "not_retested": [GROUP | {"affected": ["10.0.0.9:443/tcp"]}],
    "endpoints_added": ["10.0.0.7:443/tcp"], "endpoints_removed": [],
    "endpoint_changes": [{"endpoint_id": "10.0.0.5:443/tcp", "tls_versions": {"before": ["TLSv1.2"], "after": ["TLSv1.2", "TLSv1.3"]}}],
    "counts": {"new": 1, "fixed": 0, "persistent": 0, "not_retested": 1},
}
PAGE = {"limit": 50, "offset": 0, "total": 1}
