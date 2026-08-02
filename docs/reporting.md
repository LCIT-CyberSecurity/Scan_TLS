# TLS Scan Reporting Architecture

## Common model

`tls_scanner.exports.report_model.build_report_model()` builds the shared source of truth after grading. Renderers consume this model instead of recalculating endpoint grades, compliance, statistics, severity, finding categories, or remediation text.

The model contains scan metadata, hosts, endpoints, TLS versions, cipher suite observations, certificates, structured findings, finding occurrences, policies, policy compliance summaries, PQC observations, untested checks, errors, raw rows, and statistics.

## Statistics formulas

All executive metrics are endpoint based unless explicitly stated otherwise.

- `total_hosts`: unique logical host identifiers.
- `total_endpoints`: unique `ip + port + protocol` endpoint identifiers.
- `grade_distribution`: each endpoint contributes once using its overall grade.
- `compliant_endpoints`: endpoints with observed compliant rows and no failing row.
- `non_compliant_endpoints`: endpoints with at least one failing row.
- `unique_findings`: grouped by stable `finding_id`.
- `finding_occurrences`: every finding-to-endpoint observation.
- `tls_version_distribution`: endpoints supporting each version; one endpoint may appear in several TLS version buckets.
- `checks_not_tested`: sum of controls explicitly marked `Not Tested` for endpoints.

## Adding a finding

Add a stable identifier and definition to `FINDING_DEFINITIONS` in `report_model.py`. The visible title is not the identifier. Then map scanner evidence to the identifier in `classify_finding()` or in the endpoint aggregation block for certificate/PQC-specific findings.

Required fields are: finding ID, title, category, severity, status, description, technical impact, evidence, remediation, affected endpoint IDs, policy IDs, and references when available.

## Adding a chart

Add the aggregate data to `ReportStatistics`, compute it in `build_statistics()`, then render it in `tls_scanner/exports/assets/html/js/report.js` using `bars()` or `donut()`. Keep charts readable offline, printable, labelled with units, and backed by text alternatives.

## Adding a section

Add the data to the report model first. Then update the relevant renderer: `html_report.py` for structure, `assets/html/js/report.js` for dynamic rendering, `markdown_report.py` for text output, and tests in `test_tls_scanner.py`.

## Renderers

- HTML: product-style, offline, file:// compatible, local CSS/JS only, data embedded in JSON and inserted into the DOM with `textContent`.
- PDF: generated from the local HTML renderer with Google Chrome or Chromium headless print mode; no network access is required.
- Markdown: executive and technical summary using the common model.
- CSV: row-level scan export remains compatible; findings CSV is structured and grouped.
- CBOM: CycloneDX 1.6 cryptographic assets generated from scan rows for compatibility.

## Security notes

HTML scan data is JSON escaped before embedding. The JavaScript renderer builds nodes using DOM APIs and assigns untrusted values with `textContent`. No external URLs, CDNs, remote fonts, analytics, or network calls are used.
