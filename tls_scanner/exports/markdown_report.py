"""
Markdown dashboard report builder.

Called by:
- `tls_scanner.exports.paths.write_exports`, when the `md` format is requested;
- Markdown report tests.

Produces:
- a standalone Markdown report with indicators, charts, host summary, and technical details.
"""

from ..config import config_targets_to_list


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
                "failed_reasons_by_port": {},
            },
        )
        port = row[2]
        host_summary["ports"].add(port)

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
        "| Signal | Statut | IP | FQDN | Ports | Raison |",
        "| --- | --- | --- | --- | --- | --- |",
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
                        summary["reason"],
                    ]
                )
                + " |"
            )
    else:
        lines.append("| - | Aucun resultat | - | - | - | Aucun controle exploitable |")

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
    header.extend(["Compliance", "Reason"])
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
