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


GRADE_ORDER = {"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "F": 5}


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


def build_security_findings(results):
    findings = []
    seen = set()
    for row in results:
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
        "| Element | Count | Graphique |",
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
    security_findings = build_security_findings(results)
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
