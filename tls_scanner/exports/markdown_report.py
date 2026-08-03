"""
Markdown dashboard report builder.

Called by:
- `tls_scanner.exports.paths.write_exports`, when the `md` format is requested;
- Markdown report tests.

Produces:
- a standalone Markdown report with indicators, charts, host summary, and technical details.
"""

from ..config import config_targets_to_list
from ..models import SecurityFinding


def markdown_escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def sort_port(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return str(value)


def percent(part, total):
    if total == 0:
        return 0
    return round(part * 100 / total)


def dashboard_bar(part, total, width=18):
    if total == 0:
        filled = 0
    else:
        filled = round(part * width / total)
    return "█" * filled + "░" * (width - filled)


def count_values(values):
    counts = {}
    for value in values:
        if value:
            counts[value] = counts.get(value, 0) + 1
    return counts


GRADE_ORDER = {"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "F": 5, "Not Tested": 6}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "none": 5}


def endpoint_host_key(endpoint):
    return endpoint.hostname or endpoint.ip_address or endpoint.host_id or endpoint.endpoint_id


def group_model_endpoints(endpoints):
    grouped = {}
    for endpoint in endpoints:
        grouped.setdefault(endpoint_host_key(endpoint), []).append(endpoint)
    return [
        (host, sorted(items, key=lambda endpoint: (sort_port(endpoint.port), endpoint.endpoint_id)))
        for host, items in sorted(grouped.items(), key=lambda item: item[0])
    ]


def worst_model_grade(endpoints):
    return max((endpoint.overall_grade for endpoint in endpoints), key=lambda grade: GRADE_ORDER.get(grade, 99), default="Not Tested")


def highest_model_severity(endpoints):
    return min((endpoint.highest_severity for endpoint in endpoints), key=lambda severity: SEVERITY_ORDER.get(severity, 99), default="none")


def joined_unique(values):
    items = sorted({str(value) for value in values if value not in {None, ""}})
    return ", ".join(items) if items else "Not Tested"


def model_endpoint_summary_row(host, endpoints):
    findings = sum(endpoint.finding_count for endpoint in endpoints)
    failed = sum(1 for endpoint in endpoints if endpoint.compliance_status != "compliant")
    ports = ", ".join(f"{endpoint.port}/{endpoint.protocol}" for endpoint in endpoints)
    protocols = joined_unique(version for endpoint in endpoints for version in endpoint.supported_tls_versions)
    certificates = joined_unique(endpoint.certificate.valid_until or endpoint.certificate.status for endpoint in endpoints)
    pqc = joined_unique(endpoint.pqc.get("readiness") for endpoint in endpoints)
    return [host, len(endpoints), ports, worst_model_grade(endpoints), f"{failed}/{len(endpoints)}", findings, highest_model_severity(endpoints), certificates, protocols, pqc]


def worst_grade(grades):
    known_grades = [grade for grade in grades if grade in GRADE_ORDER]
    if not known_grades:
        return "-"
    return max(known_grades, key=GRADE_ORDER.get)


def unique_summary(values):
    cleaned = sorted({str(value) for value in values if value not in {None, ""}})
    if not cleaned:
        return "-"
    if len(cleaned) == 1:
        return cleaned[0]
    return "mixed"


def earliest_date(values):
    dates = sorted(str(value) for value in values if value and value != "N/A")
    return dates[0] if dates else "N/A"


def certificate_rows(results):
    rows_by_endpoint = {}
    for row in results:
        if len(row) < 13:
            continue
        has_detailed_certificate = len(row) >= 19
        key = (row[0], row[1], row[2])
        rows_by_endpoint.setdefault(
            key,
            {
                "ip": row[0],
                "fqdn": row[1] or "-",
                "port": row[2],
                "self_signed": row[9] if has_detailed_certificate else row[-6],
                "certificate_crypto": row[8] if has_detailed_certificate else row[-7],
                "days_left": row[10] if has_detailed_certificate else "unknown",
                "issuer": row[11] if has_detailed_certificate else row[-5],
                "subject": row[12] if has_detailed_certificate else row[-4],
                "san": row[13] if has_detailed_certificate else row[-3],
                "key_type": row[14] if has_detailed_certificate else "unknown",
                "key_size": row[15] if has_detailed_certificate else "unknown",
                "signature_algorithm": row[16] if has_detailed_certificate else "unknown",
                "expiry": row[7],
            },
        )
    return sorted(
        rows_by_endpoint.values(),
        key=lambda row: (row["ip"], sort_port(row["port"])),
    )


def is_detailed_certificate_row(row):
    return len(row) >= 19


def parse_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def certificate_detail_findings(row, expires_within_days=30):
    if not is_detailed_certificate_row(row):
        return []

    findings = []
    ip, fqdn, port = row[0], row[1] or "-", row[2]
    days_left = parse_int(row[10])
    key_type = str(row[14]).upper()
    key_size = parse_int(row[15])
    signature_algorithm = str(row[16])
    normalized_signature = signature_algorithm.upper().replace("-", "").replace("_", "")

    def add(check, status, severity, evidence, remediation):
        findings.append(
            SecurityFinding(
                ip=ip,
                fqdn=fqdn,
                port=port,
                check=check,
                status=status,
                severity=severity,
                evidence=evidence,
                remediation=remediation,
            )
        )

    if days_left is not None:
        if days_left < 0:
            add(
                "Expired certificate",
                "KO",
                "high",
                f"Certificate expired {abs(days_left)} day(s) ago on {row[7]}",
                "Renew and deploy a valid certificate.",
            )
        elif days_left <= expires_within_days:
            add(
                "Certificate expires soon",
                "WARNING",
                "medium",
                f"Certificate expires in {days_left} day(s) on {row[7]}",
                "Plan certificate renewal before expiration.",
            )

    if "MD5" in normalized_signature or "SHA1" in normalized_signature or normalized_signature.endswith("SHA"):
        add(
            "Weak certificate signature",
            "KO",
            "medium",
            f"Certificate signature algorithm is {signature_algorithm}",
            "Replace the certificate with one signed using SHA-256 or stronger.",
        )

    if key_type == "RSA" and key_size is not None and key_size < 2048:
        add(
            "Weak certificate key",
            "KO",
            "high",
            f"Certificate uses RSA {key_size}-bit key",
            "Replace the certificate with an RSA key of at least 2048 bits.",
        )

    return findings


def classify_security_reason(reason):
    normalized = str(reason).casefold()
    if "tls" in normalized and ("1.0" in normalized or "1.1" in normalized or "version" in normalized):
        return (
            "Deprecated TLS version",
            "high",
            "Disable deprecated TLS versions and allow only TLS 1.2 or TLS 1.3.",
        )
    if "sha-1" in normalized or "sha1" in normalized or "signature hash" in normalized:
        return (
            "Weak signature hash",
            "medium",
            "Replace certificates or cipher suites that rely on SHA-1/MD5 with SHA-256 or stronger.",
        )
    if "rsa key" in normalized:
        return (
            "Weak certificate key",
            "medium",
            "Replace the certificate with an RSA key of at least 2048 bits, preferably 3072 bits or stronger where required.",
        )
    if "certificate expired" in normalized:
        return (
            "Expired certificate",
            "high",
            "Renew and deploy a valid certificate.",
        )
    if "certificate date" in normalized:
        return (
            "Unreadable certificate validity",
            "medium",
            "Verify the certificate validity dates and replace malformed certificates.",
        )
    if "cipher" in normalized:
        return (
            "Weak cipher suite",
            "medium",
            "Disable weak cipher suites and prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
        )
    return (
        "TLS compliance failure",
        "medium",
        "Review the TLS configuration and align it with the selected encryption policy.",
    )


def build_security_findings(results, include_certificate_findings=True, expires_within_days=30):
    findings = []
    seen = set()
    for row in results:
        certificate_findings = (
            certificate_detail_findings(row, expires_within_days)
            if include_certificate_findings
            else []
        )
        for finding in certificate_findings:
            finding_key = (
                finding.ip,
                finding.fqdn,
                finding.port,
                finding.check,
                finding.evidence,
            )
            if finding_key not in seen:
                seen.add(finding_key)
                findings.append(finding)

        if len(row) < 10 or row[-2] != "KO":
            continue
        reason = row[-1] or "TLS compliance failure"
        check, severity, remediation = classify_security_reason(reason)
        evidence_parts = [str(reason)]
        if len(row) > 5:
            evidence_parts.append(f"{row[4]} {row[5]}")
        evidence = " - ".join(evidence_parts)
        finding_key = (row[0], row[1], row[2], check, evidence)
        if finding_key in seen:
            continue
        seen.add(finding_key)
        findings.append(
            SecurityFinding(
                ip=row[0],
                fqdn=row[1] or "-",
                port=row[2],
                check=check,
                status="KO",
                severity=severity,
                evidence=evidence,
                remediation=remediation,
            )
        )
    return sorted(
        findings,
        key=lambda finding: (finding.severity, finding.ip, sort_port(finding.port), finding.check),
    )


# Use plain Markdown bars so the dashboard remains readable even when Mermaid is unsupported.
def append_bar_chart(lines, title, counts):
    lines.extend([
        "",
        f"### {title}",
        "",
        "| Element | Count | Chart |",
        "| --- | ---: | --- |",
    ])
    if not counts:
        lines.append("| - | 0 | - |")
        return

    total = sum(counts.values())
    for label, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        lines.append(
            f"| {markdown_escape(label)} | {count} | "
            f"{dashboard_bar(count, total)} {percent(count, total)}% |"
        )


# A host is non-compliant as soon as one observed check fails.
def build_host_compliance_summary(results):
    hosts = {}
    for row in results:
        if len(row) < 4:
            continue

        key = (row[0], row[1])
        host_summary = hosts.setdefault(
            key,
            {
                "ip": row[0],
                "fqdn": row[1] or "-",
                "ports": set(),
                "grades": [],
                "self_signed": [],
                "certificate_expiries": [],
                "certificate_issuers": [],
                "failed_reasons_by_port": {},
            },
        )
        port = row[2]
        host_summary["ports"].add(port)
        host_summary["grades"].append(row[3])
        if len(row) >= 13:
            has_detailed_certificate = len(row) >= 19
            host_summary["self_signed"].append(
                row[9] if has_detailed_certificate else row[-6]
            )
            host_summary["certificate_expiries"].append(row[7])
            host_summary["certificate_issuers"].append(
                row[11] if has_detailed_certificate else row[-5]
            )

        if row[-2] == "KO":
            reason = row[-1] or "Contrôle non conforme"
            host_summary["failed_reasons_by_port"].setdefault(port, set()).add(reason)

    summaries = []
    for host_summary in hosts.values():
        failed_reasons_by_port = host_summary["failed_reasons_by_port"]
        if failed_reasons_by_port:
            status = "NON CONFORME"
            signal = "ALERTE"
            reason_parts = []
            for port, reasons in sorted(
                failed_reasons_by_port.items(),
                key=lambda item: sort_port(item[0]),
            ):
                reason_parts.append(f"port {port}: {', '.join(sorted(reasons))}")
            reason = "; ".join(reason_parts)
        else:
            status = "CONFORME"
            signal = "OK"
            reason = "Tous les contrôles observés sont conformes."

        summaries.append(
            {
                "signal": signal,
                "status": status,
                "ip": host_summary["ip"],
                "fqdn": host_summary["fqdn"],
                "ports": ", ".join(
                    str(port)
                    for port in sorted(host_summary["ports"], key=sort_port)
                ),
                "worst_grade": worst_grade(host_summary["grades"]),
                "self_signed": unique_summary(host_summary["self_signed"]),
                "certificate_expiry": earliest_date(host_summary["certificate_expiries"]),
                "certificate_issuer": unique_summary(host_summary["certificate_issuers"]),
                "reason": reason,
            }
        )

    return sorted(
        summaries,
        key=lambda summary: (summary["status"] == "CONFORME", summary["ip"]),
    )


# Keep the report self-contained: Mermaid is optional, table bars remain readable everywhere.
def build_markdown_report(results, job, scan_timestamp):
    ok_count = sum(1 for row in results if row[-2] == "OK")
    ko_count = sum(1 for row in results if row[-2] == "KO")
    total_checks = ok_count + ko_count
    grade_counts = count_values(row[3] for row in results if len(row) > 3)
    reason_counts = count_values(row[-1] for row in results if row[-2] == "KO")
    host_summaries = build_host_compliance_summary(results)
    cert_rows = certificate_rows(results)
    security_findings = build_security_findings(
        results,
        include_certificate_findings=job.certificate_findings_enabled,
        expires_within_days=job.certificate_expires_within_days,
    )
    compliant_hosts = sum(1 for row in host_summaries if row["status"] == "CONFORME")
    non_compliant_hosts = sum(
        1 for row in host_summaries if row["status"] == "NON CONFORME"
    )
    total_hosts = compliant_hosts + non_compliant_hosts
    policies = job.policies or ()
    target_groups = job.target_groups or ()
    lines = [
        f"# TLS Scan Dashboard - {job.report_name}",
        "",
        "**Vue exécutive de la posture TLS, des écarts de conformité et des actions prioritaires.**",
        "",
        "---",
        "",
        "## Dashboard",
        "",
        "| Indicateur | Valeur | Signal |",
        "| --- | ---: | --- |",
        f"| Hosts analyses | {total_hosts} | {dashboard_bar(total_hosts, total_hosts)} |",
        f"| Hosts conformes | {compliant_hosts} | {dashboard_bar(compliant_hosts, total_hosts)} {percent(compliant_hosts, total_hosts)}% |",
        f"| Hosts non conformes | {non_compliant_hosts} | {dashboard_bar(non_compliant_hosts, total_hosts)} {percent(non_compliant_hosts, total_hosts)}% |",
        f"| Controles OK | {ok_count} | {dashboard_bar(ok_count, total_checks)} {percent(ok_count, total_checks)}% |",
        f"| Controles KO | {ko_count} | {dashboard_bar(ko_count, total_checks)} {percent(ko_count, total_checks)}% |",
        "",
        "```mermaid",
        "pie showData",
        f'    "Hosts conformes" : {compliant_hosts}',
        f'    "Hosts non conformes" : {non_compliant_hosts}',
        "```",
    ]
    append_bar_chart(lines, "Répartition des grades", grade_counts)
    append_bar_chart(lines, "Top raisons de non-conformité", reason_counts)
    lines.extend([
        "",
        "## Conformité par host",
        "",
        "| Signal | Statut | IP | FQDN | Ports | Grade | Self-signed | Cert Expiry | Issuer | Raison |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    if host_summaries:
        for summary in host_summaries:
            lines.append(
                "| "
                + " | ".join(
                    markdown_escape(value)
                    for value in [
                        summary["signal"],
                        summary["status"],
                        summary["ip"],
                        summary["fqdn"],
                        summary["ports"],
                        summary["worst_grade"],
                        summary["self_signed"],
                        summary["certificate_expiry"],
                        summary["certificate_issuer"],
                        summary["reason"],
                    ]
                )
                + " |"
            )
    else:
        lines.append("| - | Aucun resultat | - | - | - | - | - | - | - | Aucun controle exploitable |")


    lines.extend([
        "",
        "## Certificates",
        "",
        "| IP | FQDN | Port | Self-signed | Certificate Crypto | Expiry | Days Left | Issuer | Subject | SAN | Key Type | Key Size | Signature Algorithm |",
        "| --- | --- | ---: | --- | --- | --- | ---: | --- | --- | --- | --- | ---: | --- |",
    ])
    if cert_rows:
        for cert_row in cert_rows:
            lines.append(
                "| "
                + " | ".join(
                    markdown_escape(value)
                    for value in [
                        cert_row["ip"],
                        cert_row["fqdn"],
                        cert_row["port"],
                        cert_row["self_signed"],
                        cert_row["certificate_crypto"],
                        cert_row["expiry"],
                        cert_row["days_left"],
                        cert_row["issuer"],
                        cert_row["subject"],
                        cert_row["san"],
                        cert_row["key_type"],
                        cert_row["key_size"],
                        cert_row["signature_algorithm"],
                    ]
                )
                + " |"
            )
    else:
        lines.append("| - | - | - | unknown | unknown | N/A | unknown | - | - | - | unknown | unknown | unknown |")


    lines.extend([
        "",
        "## Security Findings",
        "",
        "| Severity | Status | IP | FQDN | Port | Check | Evidence | Remediation |",
        "| --- | --- | --- | --- | ---: | --- | --- | --- |",
    ])
    if security_findings:
        for finding in security_findings:
            lines.append(
                "| "
                + " | ".join(
                    markdown_escape(value)
                    for value in [
                        finding.severity,
                        finding.status,
                        finding.ip,
                        finding.fqdn,
                        finding.port,
                        finding.check,
                        finding.evidence,
                        finding.remediation,
                    ]
                )
                + " |"
            )
    else:
        lines.append("| - | - | - | - | - | No security finding | - | - |")

    lines.extend([
        "",
        "## Contexte du scan",
        "",
        "| Champ | Valeur |",
        "| --- | --- |",
        f"| Generated | {markdown_escape(scan_timestamp)} |",
        f"| Scan run ID | {markdown_escape(job.scan_run_id)} |",
        f"| Report | {markdown_escape(job.report_name)} |",
        f"| Frequency | {markdown_escape(job.frequency)} |",
        f"| Policy mode | {markdown_escape(job.policy_mode)} |",
        f"| Ports | {markdown_escape(job.ports)} |",
        f"| Crypto profile | {markdown_escape(job.crypto)} |",
        f"| DNS resolution | {'disabled' if job.ip else 'enabled'} |",
        "",
        "## Target Groups",
        "",
    ])
    if target_groups:
        for group in target_groups:
            description = f" - {group.description}" if group.description else ""
            lines.append(f"- {group.name}: {len(group.targets)} targets{description}")
    else:
        lines.append(f"- manual: {len(config_targets_to_list(job.targets))} targets")

    lines.extend(["", "## Policies", ""])
    if policies:
        for policy in policies:
            version = f" v{policy.version}" if policy.version else ""
            description = f" - {policy.description}" if policy.description else ""
            lines.append(f"- {policy.name}{version}{description}")
    else:
        lines.append("- Legacy scanner policy")

    failed_rows = [row for row in results if row[-2] == "KO"]
    lines.extend([
        "",
        "## Actions prioritaires",
        "",
        "| IP | FQDN | Port | Grade | TLS Version | Compliance | Reason |",
        "| --- | --- | ---: | --- | --- | --- | --- |",
    ])
    if failed_rows:
        for row in failed_rows:
            lines.append(
                "| "
                + " | ".join(
                    markdown_escape(value)
                    for value in [row[0], row[1], row[2], row[3], row[4], row[-2], row[-1]]
                )
                + " |"
            )
    else:
        lines.append("| - | - | - | - | - | - | Aucun ecart detecte |")

    header = [
        "IP",
        "FQDN",
        "Port",
        "TLS Grade" if job.crypto == "pqc" else "Grade",
        "TLS Version",
        "Cipher Suite",
        "Public Key",
        "Certificate Validity",
    ]
    if job.crypto == "pqc":
        header.append("Key Exchange")
    header.extend(
        [
            "Certificate Crypto",
            "Self-signed",
            "Certificate Days Left",
            "Certificate Issuer",
            "Certificate Subject",
            "Certificate SAN",
            "Certificate Key Type",
            "Certificate Key Size",
            "Certificate Signature Algorithm",
            "Compliance",
            "Reason",
        ]
    )
    lines.extend([
        "",
        "<details>",
        "<summary>Résultats techniques complets</summary>",
        "",
        "| " + " | ".join(header) + " |",
        "| " + " | ".join("---" for _ in header) + " |",
    ])
    for row in results:
        lines.append("| " + " | ".join(markdown_escape(value) for value in row) + " |")
    lines.extend(["", "</details>", ""])
    return "\n".join(lines)



def build_markdown_report_from_model(model):
    stats = model.statistics
    lines = [
        f"# TLS Security Report - {model.metadata.report_name}",
        "",
        "## Executive Summary",
        "",
        f"Overall Grade: **{stats.overall_grade}**",
        "",
        f"Compliance Status: **{stats.compliance_status}**",
        "",
        f"Scan Date: {markdown_escape(model.metadata.scan_timestamp)}  ",
        f"Scan Run ID: {markdown_escape(model.metadata.scan_run_id)}  ",
        f"Scanner Version: {markdown_escape(model.metadata.scanner_version)}  ",
        f"Selected Policies: {markdown_escape(', '.join(policy.name + (' v' + policy.version if policy.version else '') for policy in model.policies) or 'Legacy scanner policy')}",
        f"Target Groups: {markdown_escape(', '.join(model.metadata.target_groups) or 'manual')}",
        "",
        "Overall TLS security posture "
        + ("is strong." if stats.compliance_status == "Compliant" else "requires improvement."),
        "",
        "## Endpoint Statistics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total Hosts | {stats.total_hosts} |",
        f"| Total Endpoints | {stats.total_endpoints} |",
        f"| Compliant Endpoints | {stats.compliant_endpoints} |",
        f"| Non-Compliant Endpoints | {stats.non_compliant_endpoints} |",
        f"| Endpoints with Errors | {stats.endpoints_with_errors} |",
        f"| Unique Findings | {stats.unique_findings} |",
        f"| Finding Occurrences | {stats.finding_occurrences} |",
        f"| Checks Not Tested | {stats.checks_not_tested} |",
    ]
    append_bar_chart(lines, "Grade Distribution", stats.grade_distribution)
    append_bar_chart(lines, "Top Findings by Affected Endpoint", {item["title"]: item["affected_endpoints"] for item in stats.top_findings})
    append_bar_chart(lines, "TLS Version Distribution", stats.tls_version_distribution)
    lines.extend([
        "",
        "## Endpoint Summary",
        "",
        "| Host | Endpoints | Ports | Worst Grade | Failed Endpoints | Findings | Highest Severity | Certificate Expiration | TLS Versions | PQC Readiness |",
        "| --- | ---: | --- | --- | --- | ---: | --- | --- | --- | --- |",
    ])
    for host, endpoints in group_model_endpoints(model.endpoints):
        lines.append("| " + " | ".join(markdown_escape(value) for value in model_endpoint_summary_row(host, endpoints)) + " |")
    lines.extend([
        "",
        "## Communication Security",
        "",
        "| Endpoint | Host | Port | TLS Version | Cipher Suite | Key Exchange | Authentication | Encryption | Hash | Forward Secrecy | Strength | Compliance | Policy Reason |",
        "| --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for endpoint in model.endpoints:
        for suite in endpoint.cipher_suites:
            lines.append("| " + " | ".join(markdown_escape(value) for value in [endpoint.endpoint_id, endpoint.hostname, endpoint.port, suite.tls_version, suite.name, suite.key_exchange, suite.authentication, suite.encryption, suite.hash_algorithm, suite.forward_secrecy, suite.strength, suite.compliance_status, suite.policy_reason]) + " |")
    lines.extend([
        "",
        "## Certificate Inventory",
        "",
        "| Endpoint | Subject | Issuer | SAN | Expiration | Remaining Days | Status | Key | Signature | Trust | Hostname Validation | Chain Validation | Revocation |",
        "| --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for endpoint in model.endpoints:
        cert = endpoint.certificate
        key = f"{cert.key_type} {cert.key_size or ''}".strip()
        lines.append("| " + " | ".join(markdown_escape(value) for value in [endpoint.endpoint_id, cert.subject, cert.issuer, ', '.join(cert.san), cert.valid_until, cert.remaining_days if cert.remaining_days is not None else 'unknown', cert.status, key, cert.signature_algorithm, cert.trust_status, cert.hostname_validation_status, cert.chain_validation_status, cert.revocation_status]) + " |")
    lines.extend([
        "",
        "## Compliance",
        "",
        "| Policy | Version | Compliance | Compliant Endpoints | Non-Compliant Endpoints | Failed Controls |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ])
    if model.policies:
        for policy in model.policies:
            lines.append("| " + " | ".join(markdown_escape(value) for value in [policy.name, policy.version or '-', f"{policy.compliance_percentage}%", policy.compliant_endpoints, policy.non_compliant_endpoints, policy.failed_controls]) + " |")
    else:
        lines.append("| Legacy scanner policy | - | 0% | 0 | 0 | 0 |")
    lines.extend([
        "",
        "## PQC Readiness",
        "",
        "| Indicator | Value |",
        "| --- | ---: |",
    ])
    for label, value in stats.pqc_readiness.items():
        lines.append(f"| {markdown_escape(label)} | {markdown_escape(value)} |")
    lines.extend(["", "## Security Findings", ""])
    if model.findings:
        for finding in model.findings:
            lines.extend([
                f"### {markdown_escape(finding.title)}",
                "",
                f"- Identifier: `{markdown_escape(finding.finding_id)}`",
                f"- Severity: {markdown_escape(finding.severity.title())}",
                f"- Category: {markdown_escape(finding.category)}",
                f"- Affected Endpoints: {len(finding.affected_endpoint_ids)}",
                f"- Description: {markdown_escape(finding.description)}",
                f"- Technical Impact: {markdown_escape(finding.technical_impact)}",
                f"- Evidence: {markdown_escape(finding.evidence)}",
                f"- Remediation: {markdown_escape(finding.remediation)}",
                f"- Policies: {markdown_escape(', '.join(finding.policy_ids) or 'None')}",
                "",
            ])
    else:
        lines.append("No security findings were generated.")
    lines.extend([
        "",
        "## Technical Details",
        "",
        "<details>",
        "<summary>Complete endpoint observations</summary>",
        "",
    ])
    for endpoint in model.endpoints:
        lines.extend([f"### {markdown_escape(endpoint.endpoint_id)}", "", "| TLS Version | Cipher Suite | Compliance | Reason |", "| --- | --- | --- | --- |"])
        for suite in endpoint.cipher_suites:
            lines.append("| " + " | ".join(markdown_escape(value) for value in [suite.tls_version, suite.name, suite.compliance_status, suite.policy_reason]) + " |")
        lines.append("")
    lines.extend(["</details>", ""])
    return "\n".join(lines)


def build_markdown_report(results, job, scan_timestamp):
    from .report_model import build_report_model

    return build_markdown_report_from_model(build_report_model(results, job, scan_timestamp))
