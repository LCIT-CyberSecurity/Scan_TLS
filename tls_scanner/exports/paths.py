"""
Export path, timestamp, and file-writing orchestration.

Called by:
- `tls_scanner.cli`, after the `ScanJob` and scan results are available;
- export path tests.

Produces:
- output file paths;
- scan/report timestamps;
- requested CSV, Markdown, or CBOM files.
"""

import csv
import json
from datetime import datetime
from pathlib import Path

from ..config import validate_config_name
from ..models import ConfigError
from .cbom import build_cbom
from .csv_export import build_csv_export
from .findings_csv import build_findings_csv_export
from .html_report import build_html_report
from .markdown_report import build_markdown_report


def local_report_timestamp():
    return datetime.now().strftime("%Y-%m-%d-%H%M%S")


def local_scan_timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def export_extension(export_format):
    if export_format == "cbom":
        return ".cbom.json"
    if export_format == "md":
        return ".md"
    if export_format == "html":
        return ".html"
    if export_format == "csv":
        return ".csv"
    raise ConfigError(f"unsupported export format: {export_format}")


# Reject path components in templates to prevent exports from escaping the configured directory.
def build_export_paths(job, timestamp):
    if job.csv_filename:
        return {job.export_format or "csv": Path(job.csv_filename)}
    if not job.export_formats:
        return {}
    report_name = validate_config_name(job.report_name, "report.name")
    basename = job.filename_template.format(
        timestamp=timestamp,
        report_name=report_name,
        scan_run_id=job.scan_run_id,
    )
    if "/" in basename or "\\" in basename or ".." in basename:
        raise ConfigError("export.filename_template must not create directories")
    export_dir = Path(job.export_directory)
    return {
        export_format: export_dir / f"{basename}{export_extension(export_format)}"
        for export_format in job.export_formats
    }


def findings_sidecar_path(export_path):
    return export_path.with_name(f"{export_path.stem}_findings.csv")


def write_findings_sidecar(results, job, export_path):
    findings_path = findings_sidecar_path(export_path)
    headers, rows = build_findings_csv_export(
        results,
        include_certificate_findings=job.certificate_findings_enabled,
        expires_within_days=job.certificate_expires_within_days,
    )
    with findings_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)
    return findings_path


def write_exports(results, job, scan_timestamp, export_paths):
    written_files = []
    written_sidecars = set()
    for export_format, export_path in export_paths.items():
        sidecar_path = None
        if export_path.parent != Path("."):
            export_path.parent.mkdir(parents=True, exist_ok=True)
        if export_format == "cbom":
            cbom = build_cbom(results, pqc=job.crypto == "pqc")
            with export_path.open("w", encoding="utf-8") as file:
                json.dump(cbom, file, indent=2)
                file.write("\n")
        elif export_format == "md":
            export_path.write_text(
                build_markdown_report(results, job, scan_timestamp),
                encoding="utf-8",
            )
            sidecar_path = write_findings_sidecar(results, job, export_path)
        elif export_format == "html":
            export_path.write_text(
                build_html_report(results, job, scan_timestamp),
                encoding="utf-8",
            )
            sidecar_path = write_findings_sidecar(results, job, export_path)
        else:
            csv_headers, csv_rows = build_csv_export(results, job, scan_timestamp)
            with export_path.open("w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(csv_headers)
                writer.writerows(csv_rows)
        written_files.append(str(export_path))
        if sidecar_path is not None and sidecar_path not in written_sidecars:
            written_files.append(str(sidecar_path))
            written_sidecars.add(sidecar_path)
    return written_files
