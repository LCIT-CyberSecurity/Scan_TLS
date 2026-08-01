"""
Professional HTML report renderer.

The report is file:// compatible: data is embedded in the document and all
presentation/runtime assets are copied next to the HTML file by the export layer.
"""

from __future__ import annotations

import html
import json

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
    posture = "is strong" if stats.compliance_status == "Compliant" else "requires improvement" if stats.non_compliant_endpoints else "is incomplete"
    top = ", ".join(item["title"].lower() for item in stats.top_findings[:3]) or "no recurring weaknesses"
    return (
        f"Overall TLS security posture {posture}. "
        f"{stats.non_compliant_endpoints} endpoint(s) are non-compliant and {stats.endpoints_with_errors} endpoint(s) have scan errors. "
        f"The main observations are {top}."
    )


def build_html_report_from_model(model: ReportModel):
    title = html.escape(f"TLS Security Report - {model.metadata.report_name}")
    data = _json_for_html(report_model_to_dict(model))
    summary = html.escape(build_executive_summary(model))
    parts = [
        "<!doctype html>", '<html lang="en">', "<head>",
        '  <meta charset="utf-8">', '  <meta name="viewport" content="width=device-width, initial-scale=1">',
        '  <meta name="referrer" content="no-referrer">', f"  <title>{title}</title>",
        '  <link rel="stylesheet" href="assets/css/report.css">',
        '  <link rel="stylesheet" href="assets/css/print.css" media="print">', "</head>", "<body>",
        '  <a class="skip-link" href="#main">Skip to main content</a>',
        '  <header class="app-shell no-print"><div class="brand-mark" aria-hidden="true">TS</div><nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#findings">Findings</a><a href="#endpoints">Endpoints</a><a href="#certificates">Certificates</a><a href="#compliance">Compliance</a><a href="#pqc">PQC</a></nav><button class="button" type="button" id="printReport">Print / Save as PDF</button></header>',
        '  <main id="main" class="report-root">',
        '    <section class="hero" id="overview"><div><p class="eyebrow">TLS Scan Report</p>',
        f'    <h1>{title}</h1><p class="summary-text" id="executiveSummary">{summary}</p></div>',
        '    <div class="hero-score" aria-label="Overall grade and compliance status"><span class="score-label">Overall Grade</span><strong id="overallGrade">-</strong><span id="overallCompliance">Not Tested</span></div></section>',
        '    <section id="scanContext" class="context-grid" aria-label="Scan context"></section>',
        '    <section id="kpis" class="kpi-grid" aria-label="Executive key performance indicators"></section>',
        '    <section class="section-grid charts-grid" id="charts" aria-label="Security statistics"></section>',
        '    <section class="panel" id="findings"><div class="section-heading"><div><p class="eyebrow">Grouped Risk</p><h2>Security Findings</h2></div></div><div id="findingFilters" class="filters no-print"></div><div id="findingsList" class="stack"></div></section>',
        '    <section class="panel" id="endpoints"><div class="section-heading"><div><p class="eyebrow">Technical Scope</p><h2>Endpoints</h2></div></div><div id="endpointFilters" class="filters no-print"></div><div id="endpointTable"></div></section>',
        '    <section class="panel" id="certificates"><div class="section-heading"><div><p class="eyebrow">PKI Inventory</p><h2>Certificates</h2></div></div><div id="certificateFilters" class="filters no-print"></div><div id="certificateTable"></div></section>',
        '    <section class="panel" id="compliance"><div class="section-heading"><div><p class="eyebrow">Policy Results</p><h2>Compliance</h2></div></div><div id="policyCompliance" class="stack"></div></section>',
        '    <section class="panel" id="pqc"><div class="section-heading"><div><p class="eyebrow">Internal Readiness Indicator</p><h2>PQC Readiness</h2></div></div><div id="pqcReadiness" class="section-grid"></div></section>',
        '    <section class="panel"><details><summary>Complete Technical Details</summary><div id="technicalDetails"></div></details></section>',
        '  </main><aside class="drawer" id="endpointDrawer" aria-hidden="true" aria-labelledby="drawerTitle"><button class="icon-button no-print" type="button" id="closeDrawer" aria-label="Close endpoint details">x</button><div id="drawerContent"></div></aside><div class="drawer-backdrop no-print" id="drawerBackdrop"></div>',
        f'  <script id="report-data" type="application/json">{data}</script>',
        '  <script src="assets/js/report.js"></script>', "</body>", "</html>",
    ]
    return "\n".join(parts) + "\n"


def build_html_report(results, job, scan_timestamp):
    return build_html_report_from_model(build_report_model(results, job, scan_timestamp))
