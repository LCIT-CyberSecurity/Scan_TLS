"""
Professional HTML report renderer.

The report is file:// compatible: data is embedded in the document and all
presentation/runtime assets are copied next to the HTML file by the export layer.
"""

from __future__ import annotations

import html
import json
from datetime import datetime

from .report_model import ReportModel, build_report_model, report_model_to_dict


HTML_ASSET_MANIFEST = {
    "css/report.css": "tls_scanner/exports/assets/html/css/report.css",
    "css/print.css": "tls_scanner/exports/assets/html/css/print.css",
    "js/report.js": "tls_scanner/exports/assets/html/js/report.js",
}


def _json_for_html(value):
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def build_executive_summary(model: ReportModel):
    stats = model.statistics
    if stats.compliance_status == "Compliant":
        posture = "strong"
        compliance = "all tested endpoints met the selected policy"
    elif stats.non_compliant_endpoints:
        posture = "exposed and requires focused remediation"
        compliance = f"{stats.non_compliant_endpoints} endpoint(s) failed the selected policy"
    else:
        posture = "partially assessed"
        compliance = "some endpoints could not be fully evaluated"
    top = ", ".join(item["title"].lower() for item in stats.top_findings[:3]) or "no recurring weaknesses"
    priority = (
        f"Priority should be given to {top}."
        if stats.top_findings
        else "No major recurring remediation theme was identified in this scan."
    )
    return (
        f"The TLS security posture is {posture}. "
        f"The scan covered {stats.total_hosts} host(s) and {stats.total_endpoints} endpoint(s); {compliance}. "
        f"It identified {stats.critical_findings} critical and {stats.high_findings} high-risk finding(s), "
        f"with {stats.finding_occurrences} total finding occurrence(s). {priority}"
    )


def _display_report_date(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    return parsed.strftime("%Y-%m-%d %H:%M")


def build_html_report_from_model(model: ReportModel):
    title = html.escape(f"TLS Security Report - {model.metadata.report_name}")
    report_name = html.escape(model.metadata.report_name)
    report_date = html.escape(_display_report_date(model.metadata.scan_timestamp))
    scanner_version = html.escape(model.metadata.scanner_version)
    data = _json_for_html(report_model_to_dict(model))
    summary = html.escape(build_executive_summary(model))
    cover = (
        '    <section class="report-cover" aria-label="Report header"><div class="cover-brand"><div class="brand-mark large" aria-hidden="true">TS</div><div><strong>TLS Scan</strong><span>Trust. Visibility. Stronger TLS.</span></div></div>'
        f'<div class="cover-meta"><span>REPORT</span><strong>{report_name}</strong><span>Produced by TLS Scan by LCIT Cybersecurity</span><span>Generated on {report_date}</span><span>v{scanner_version}</span></div></section>'
    )
    parts = [
        "<!doctype html>", '<html lang="en">', "<head>",
        '  <meta charset="utf-8">', '  <meta name="viewport" content="width=device-width, initial-scale=1">',
        '  <meta name="referrer" content="no-referrer">', f"  <title>{title}</title>",
        '  <link rel="stylesheet" href="assets/css/report.css">',
        '  <link rel="stylesheet" href="assets/css/print.css" media="print">', "</head>", "<body>",
        '  <a class="skip-link" href="#main">Skip to main content</a>',
        '  <header class="app-shell no-print"><div class="brand-block"><div class="brand-mark" aria-hidden="true">TS</div><div><strong>TLS Scan</strong><span>Security Report</span></div></div><nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#findings">Findings</a><a href="#endpoints">Endpoints</a><a href="#communication">Communication Security</a><a href="#certificates">Certificates</a><a href="#trust">Trust</a><a href="#compliance">Compliance</a><a href="#pqc">PQC</a></nav><div class="header-actions"><button class="button" type="button" id="downloadCsv">Download CSV</button><button class="button button-primary" type="button" id="printReport">Print / Save as PDF</button></div></header>',
        '  <main id="main" class="report-root">',
        cover,
        '    <section class="executive-summary" id="overview"><div class="summary-copy"><p class="eyebrow">Executive Summary</p>',
        f'    <h1 id="postureTitle">TLS security posture requires focused remediation</h1><p class="summary-text" id="executiveSummary">{summary}</p><div id="priorityActions" class="priority-strip" aria-label="Priority actions"></div></div>',
        '    </section>',
        '    <section id="kpis" class="kpi-row" aria-label="Executive key performance indicators"></section>',
        '    <section class="scan-info" aria-labelledby="scanInfoTitle"><div class="section-heading compact"><div><p class="eyebrow">Context</p><h2 id="scanInfoTitle">Scan Information</h2></div></div><div id="scanContext" class="scan-info-grid" aria-label="Scan context"></div></section>',
        '    <section class="analytics report-chapter" id="analytics" aria-label="Security analytics"><div class="chapter-heading"><p class="eyebrow">Security Analytics</p><h2>Evidence that explains the posture</h2><p>Five focused views summarize endpoint compliance, protocol exposure, certificate health, renewal urgency, and PQC readiness.</p></div><div id="charts"></div></section>',
        '    <section class="panel report-chapter top-findings-panel" id="top-findings"><div class="section-heading"><div><p class="eyebrow">Top Findings</p><h2>Priority remediation themes</h2></div><a class="text-link no-print" href="#findings">View all findings</a></div><div id="topFindingsList"></div></section>',
        '    <section class="panel report-chapter" id="findings"><div class="section-heading"><div><p class="eyebrow">Security Findings</p><h2>Detailed Findings</h2></div><span id="findingCount" class="section-count"></span></div><div id="findingFilters" class="filters no-print"></div><div id="findingsList" class="stack"></div></section>',
        '    <section class="panel report-chapter" id="endpoints"><div class="section-heading"><div><p class="eyebrow">Technical Scope</p><h2>Endpoints</h2></div><span id="endpointCount" class="section-count"></span></div><div id="endpointFilters" class="filters no-print"></div><div id="endpointTable"></div></section>',
        '    <section class="panel report-chapter" id="communication"><div class="section-heading"><div><p class="eyebrow">Encryption Inventory</p><h2>Communication Security</h2></div><span id="communicationCount" class="section-count"></span></div><div id="communicationTable"></div></section>',
        '    <section class="panel report-chapter" id="certificates"><div class="section-heading"><div><p class="eyebrow">PKI Inventory</p><h2>Certificates</h2></div></div><div id="certificateFilters" class="filters no-print"></div><div id="certificateTable"></div></section>',
        '    <section class="panel report-chapter" id="trust"><div class="section-heading"><div><p class="eyebrow">Certificate Trust</p><h2>TLS Scan Public Web PKI</h2><p class="section-subtitle">Mozilla-derived public trust store</p></div></div><div id="certificateTrust"></div></section>',
        '    <section class="panel report-chapter" id="compliance"><div class="section-heading"><div><p class="eyebrow">Policy Results</p><h2>Compliance</h2></div></div><div id="policyCompliance" class="stack"></div></section>',
        '    <section class="panel report-chapter" id="pqc"><div class="section-heading"><div><p class="eyebrow">PQC Details</p><h2>Post-Quantum Cryptography</h2></div></div><div id="pqcReadiness" class="section-grid"></div></section>',
        '    <section class="panel"><details><summary>Complete Technical Details</summary><div id="technicalDetails"></div></details></section>',
        '    <footer class="report-footer" aria-label="Report footer"><span>TLS Scan | TLS Security Report</span><span id="pageFooterMeta"></span></footer>',
        '  </main><aside class="drawer" id="endpointDrawer" aria-hidden="true" aria-labelledby="drawerTitle"><button class="icon-button no-print" type="button" id="closeDrawer" aria-label="Close endpoint details">x</button><div id="drawerContent"></div></aside><div class="drawer-backdrop no-print" id="drawerBackdrop"></div>',
        f'  <script id="report-data" type="application/json">{data}</script>',
        '  <script src="assets/js/report.js"></script>', "</body>", "</html>",
    ]
    return "\n".join(parts) + "\n"


def build_html_report(results, job, scan_timestamp):
    return build_html_report_from_model(build_report_model(results, job, scan_timestamp))
