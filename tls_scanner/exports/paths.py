"""
Export path, timestamp, and file-writing orchestration.
"""

import csv
import json
import shutil
from datetime import datetime
from pathlib import Path

from ..config import validate_config_name
from ..models import ConfigError
from .cbom import build_cbom
from .csv_export import build_csv_export
from .findings_csv import build_findings_csv_export_from_model
from .html_report import HTML_ASSET_MANIFEST, build_html_report_from_model
from .markdown_report import build_markdown_report_from_model
from .report_model import build_metadata_document, build_report_model


def local_report_timestamp():
    return datetime.now().strftime("%Y-%m-%d-%H%M%S")


def local_scan_timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def export_extension(export_format):
    extensions = {"cbom": ".cbom.json", "md": ".md", "html": ".html", "csv": ".csv"}
    try:
        return extensions[export_format]
    except KeyError as error:
        raise ConfigError(f"unsupported export format: {export_format}") from error


def build_export_basename(job, timestamp):
    report_name = validate_config_name(job.report_name, "report.name")
    basename = job.filename_template.format(timestamp=timestamp, report_name=report_name, scan_run_id=job.scan_run_id)
    if "/" in basename or "\\" in basename or ".." in basename:
        raise ConfigError("export.filename_template must not create directories")
    return basename


def build_export_paths(job, timestamp):
    if job.csv_filename:
        return {job.export_format or "csv": Path(job.csv_filename)}
    if not job.export_formats:
        return {}
    basename = build_export_basename(job, timestamp)
    scan_dir = Path(job.export_directory) / basename
    subdirs = {"csv": "csv", "md": "markdown", "html": "html", "cbom": "cbom"}
    return {fmt: scan_dir / subdirs[fmt] / f"{basename}{export_extension(fmt)}" for fmt in job.export_formats}


def findings_sidecar_path(export_path):
    return export_path.with_name(f"{export_path.stem}_findings.csv")


def scan_root_from_paths(export_paths):
    for path in export_paths.values():
        parts = path.parts
        for marker in ("csv", "markdown", "html", "cbom"):
            if marker in parts:
                index = parts.index(marker)
                if index > 0:
                    return Path(*parts[:index])
    return None


def copy_html_assets(html_path):
    asset_root = html_path.parent / "assets"
    for relative_path, source_path in HTML_ASSET_MANIFEST.items():
        target = asset_root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)
    for directory in (asset_root / "images", asset_root / "icons"):
        directory.mkdir(parents=True, exist_ok=True)


def write_findings_sidecar_from_model(model, findings_path):
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    headers, rows = build_findings_csv_export_from_model(model)
    with findings_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)
    return findings_path


def write_metadata(model, basename, export_paths, written_files):
    root = scan_root_from_paths(export_paths)
    if root is None:
        return None
    metadata_path = root / "metadata" / f"{basename}.metadata.json"
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(build_metadata_document(model, basename, written_files), indent=2) + "\n", encoding="utf-8")
    return metadata_path


def write_exports(results, job, scan_timestamp, export_paths, scan_duration_seconds=None):
    written_files = []
    model = build_report_model(results, job, scan_timestamp, scan_duration_seconds)
    basename = next(iter(export_paths.values())).name
    for suffix in (".cbom.json", ".html", ".csv", ".md"):
        basename = basename.removesuffix(suffix)
    csv_path = export_paths.get("csv")
    findings_path = findings_sidecar_path(csv_path) if csv_path else None
    for export_format, export_path in export_paths.items():
        export_path.parent.mkdir(parents=True, exist_ok=True)
        if export_format == "cbom":
            with export_path.open("w", encoding="utf-8") as file:
                json.dump(build_cbom(results, pqc=job.crypto == "pqc"), file, indent=2)
                file.write("\n")
        elif export_format == "md":
            (export_path.parent / "assets" / "images").mkdir(parents=True, exist_ok=True)
            export_path.write_text(build_markdown_report_from_model(model), encoding="utf-8")
        elif export_format == "html":
            export_path.write_text(build_html_report_from_model(model), encoding="utf-8")
            copy_html_assets(export_path)
        else:
            headers, rows = build_csv_export(results, job, scan_timestamp)
            with export_path.open("w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(headers)
                writer.writerows(rows)
        written_files.append(str(export_path))
    if findings_path is None and export_paths:
        findings_path = findings_sidecar_path(next(iter(export_paths.values())))
    if findings_path is not None and ({"md", "html", "csv"} & set(export_paths)):
        written_files.append(str(write_findings_sidecar_from_model(model, findings_path)))
    metadata_path = write_metadata(model, basename, export_paths, written_files)
    if metadata_path is not None:
        written_files.append(str(metadata_path))
    return written_files
