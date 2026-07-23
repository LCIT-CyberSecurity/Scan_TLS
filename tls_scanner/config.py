"""
YAML configuration loading, validation, and merge logic.

Called by:
- `tls_scanner.cli`, to build the executable `ScanJob`;
- configuration and report-selection tests.

Produces:
- validated `ScanJob`, `TargetGroup`, and `EncryptionPolicy` objects;
- explicit `ConfigError` exceptions for invalid configuration.
"""

import argparse
import json
from pathlib import Path

from .constants import (
    ALLOWED_EXPORT_FORMATS,
    DEFAULT_CONFIG_FILE,
    DEFAULT_EXPORT_DIR,
    DEFAULT_LOG_FILE,
    DEFAULT_POLICIES_DIR,
    DEFAULT_TARGETS_DIR,
    DEFAULT_WORKERS,
    LOG_LEVELS,
    MAX_WORKERS,
    SAFE_CONFIG_NAME,
)

DEFAULT_POLICY_NAME = "anssi_encryption_policy"
from .models import ConfigError, EncryptionPolicy, ScanJob, TargetGroup
from .network import parse_ports


# Keep YAML parsing at the boundary so the rest of the package works with dictionaries and domain objects.
def load_yaml_config(config_path):
    try:
        import yaml
    except ImportError as error:
        raise ConfigError(
            "PyYAML is required to read YAML config files. "
            "Install it with: python3 -m pip install -r requirements.txt"
        ) from error

    path = Path(config_path)
    try:
        with path.open(encoding="utf-8") as file:
            config = yaml.safe_load(file)
    except OSError as error:
        raise ConfigError(f"Unable to read config file {path}: {error}") from error
    except yaml.YAMLError as error:
        raise ConfigError(f"Invalid YAML config file {path}: {error}") from error

    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ConfigError(f"Config file {path} must contain a YAML mapping")
    return config


def require_mapping(value, name):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping")
    return value


def validate_config_name(name, field_name):
    if not isinstance(name, str) or not SAFE_CONFIG_NAME.fullmatch(name):
        raise ConfigError(f"{field_name} must contain only letters, numbers, '_' or '-'")
    return name


def list_config_reports(config):
    reports = config.get("reports", [])
    if not isinstance(reports, list):
        raise ConfigError("reports must be a list")
    names = []
    for report in reports:
        if not isinstance(report, dict):
            raise ConfigError("each report must be a mapping")
        names.append(validate_config_name(report.get("name"), "reports[].name"))
    return names


def select_config_report(config, report_name=None):
    reports = config.get("reports")
    if reports is None:
        return None
    if not isinstance(reports, list):
        raise ConfigError("reports must be a list")
    if not reports:
        raise ConfigError("reports must contain at least one report")

    indexed_reports = {}
    for report in reports:
        if not isinstance(report, dict):
            raise ConfigError("each report must be a mapping")
        name = validate_config_name(report.get("name"), "reports[].name")
        if name in indexed_reports:
            raise ConfigError(f"duplicate report name: {name}")
        indexed_reports[name] = report

    if report_name:
        validate_config_name(report_name, "--report")
        try:
            return indexed_reports[report_name]
        except KeyError as error:
            available = ", ".join(sorted(indexed_reports))
            raise ConfigError(f"unknown report '{report_name}'; available reports: {available}") from error

    if len(indexed_reports) == 1:
        return next(iter(indexed_reports.values()))

    available = ", ".join(sorted(indexed_reports))
    raise ConfigError(f"multiple reports configured; use --report NAME. Available reports: {available}")


def merge_mappings(*mappings):
    merged = {}
    for mapping in mappings:
        for key, value in require_mapping(mapping, "defaults/report section").items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = merge_mappings(merged[key], value)
            else:
                merged[key] = value
    return merged


def config_targets_to_list(targets, field_name="targets"):
    if targets is None:
        return []
    if isinstance(targets, str):
        return [targets]
    if isinstance(targets, list) and all(isinstance(target, str) for target in targets):
        return targets
    if isinstance(targets, dict):
        collected = []
        for key in ("fqdn", "ip", "subnets"):
            values = targets.get(key, [])
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                raise ConfigError(f"{field_name}.{key} must be a string or list of strings")
            collected.extend(values)
        return collected
    raise ConfigError(f"{field_name} must be a string, list of strings, or typed mapping")


def config_targets_to_cli_value(targets):
    return ",".join(config_targets_to_list(targets, "scan.targets"))


def load_target_group_file(target_file):
    config = load_yaml_config(target_file)
    name = validate_config_name(config.get("name", Path(target_file).stem), "target group name")
    targets = tuple(config_targets_to_list(config.get("targets"), f"targets file {target_file}"))
    if not targets:
        raise ConfigError(f"target group {name} must contain at least one target")
    description = config.get("description", "")
    if not isinstance(description, str):
        raise ConfigError(f"target group {name} description must be a string")
    return TargetGroup(name=name, description=description, targets=targets, path=str(target_file))


def load_named_target_groups(names):
    if isinstance(names, str):
        names = [names]
    if names is None:
        return []
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ConfigError("target_groups must be a string or list of strings")

    targets_dir = Path(DEFAULT_TARGETS_DIR)
    index = {}
    for target_file in sorted(targets_dir.glob("*.yaml")):
        group = load_target_group_file(target_file)
        if group.name in index:
            raise ConfigError(f"duplicate target group name: {group.name}")
        index[group.name] = group

    groups = []
    for name in names:
        validate_config_name(name, "target_groups[]")
        try:
            groups.append(index[name])
        except KeyError as error:
            available = ", ".join(sorted(index)) or "none"
            raise ConfigError(f"unknown target group '{name}'; available target groups: {available}") from error
    return groups


def load_report_targets(report_config):
    groups = []
    groups.extend(load_named_target_groups(report_config.get("target_groups")))

    targets_config = require_mapping(report_config.get("targets", {}), "targets")
    inline_targets = tuple(config_targets_to_list(targets_config.get("inline"), "targets.inline"))
    if inline_targets:
        report_name = report_config.get("name", "inline")
        groups.append(TargetGroup(name=f"{report_name}_inline", targets=inline_targets))

    target_files = targets_config.get("files", [])
    if isinstance(target_files, str):
        target_files = [target_files]
    if not isinstance(target_files, list) or not all(isinstance(path, str) for path in target_files):
        raise ConfigError("targets.files must be a string or list of strings")
    for target_file in target_files:
        groups.append(load_target_group_file(target_file))

    return groups


def detect_export_format(filename, explicit_export=True):
    if not filename:
        return None
    lower_filename = filename.lower()
    if lower_filename.endswith(".cbom.json"):
        return "cbom"
    if lower_filename.endswith(".md"):
        return "md"
    if lower_filename.endswith(".csv") or not explicit_export:
        return "csv"
    raise ConfigError("export.filename must end with .csv, .cbom.json, or .md")


def validate_workers(value, field_name="scan.workers"):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{field_name} must be an integer")
    if value < 1 or value > MAX_WORKERS:
        raise ConfigError(f"{field_name} must be between 1 and {MAX_WORKERS}")
    return value


def parse_ports_config(value, field_name="scan.ports"):
    if not isinstance(value, (str, int)):
        raise ConfigError(f"{field_name} must be a string or integer")
    try:
        return parse_ports(str(value))
    except argparse.ArgumentTypeError as error:
        raise ConfigError(f"{field_name} is invalid: {error}") from error


def load_policy_file(policy_file):
    config = load_yaml_config(policy_file)
    name = validate_config_name(config.get("name"), "policy name")
    version = config.get("version", "")
    description = config.get("description", "")
    if not isinstance(version, str):
        raise ConfigError(f"policy {name} version must be a string")
    if not isinstance(description, str):
        raise ConfigError(f"policy {name} description must be a string")

    tls_config = require_mapping(config.get("tls"), f"policy {name}.tls")
    tls_values = {}
    for key in ("allowed_versions", "allowed_cipher_algorithms", "allowed_signature_hashes"):
        values = tls_config.get(key)
        if not isinstance(values, list) or not values or not all(isinstance(value, str) for value in values):
            raise ConfigError(f"policy {name}.tls.{key} must be a non-empty list of strings")
        tls_values[key] = tuple(values)
    minimum_rsa_bits = tls_config.get("minimum_rsa_bits")
    if not isinstance(minimum_rsa_bits, int) or minimum_rsa_bits < 1:
        raise ConfigError(f"policy {name}.tls.minimum_rsa_bits must be a positive integer")
    return EncryptionPolicy(
        name=name,
        version=version,
        description=description,
        path=str(policy_file),
        allowed_versions=tls_values["allowed_versions"],
        allowed_cipher_algorithms=tls_values["allowed_cipher_algorithms"],
        allowed_signature_hashes=tls_values["allowed_signature_hashes"],
        minimum_rsa_bits=minimum_rsa_bits,
    )


def load_default_policy():
    return load_named_policies([DEFAULT_POLICY_NAME])[0]


def load_named_policies(names):
    if isinstance(names, str):
        names = [names]
    if names is None:
        return []
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ConfigError("encryption_policies.names must be a string or list of strings")

    policies_dir = Path(DEFAULT_POLICIES_DIR)
    index = {}
    for policy_file in sorted(policies_dir.glob("*.yaml")):
        policy = load_policy_file(policy_file)
        if policy.name in index:
            raise ConfigError(f"duplicate encryption policy name: {policy.name}")
        index[policy.name] = policy

    policies = []
    for name in names:
        validate_config_name(name, "encryption_policies.names[]")
        try:
            policies.append(index[name])
        except KeyError as error:
            available = ", ".join(sorted(index)) or "none"
            raise ConfigError(f"unknown encryption policy '{name}'; available policies: {available}") from error
    return policies


def load_report_policies(report_config):
    policies_config = require_mapping(report_config.get("encryption_policies", {}), "encryption_policies")
    mode = policies_config.get("mode", "strict_all")
    if mode != "strict_all":
        raise ConfigError("encryption_policies.mode must be strict_all")

    policies = []
    policies.extend(load_named_policies(policies_config.get("names")))

    policy_files = policies_config.get("files", [])
    if isinstance(policy_files, str):
        policy_files = [policy_files]
    if not isinstance(policy_files, list) or not all(isinstance(path, str) for path in policy_files):
        raise ConfigError("encryption_policies.files must be a string or list of strings")
    for policy_file in policy_files:
        policies.append(load_policy_file(policy_file))

    seen = set()
    unique_policies = []
    for policy in policies:
        if policy.name in seen:
            raise ConfigError(f"duplicate encryption policy in report: {policy.name}")
        seen.add(policy.name)
        unique_policies.append(policy)
    if not unique_policies:
        unique_policies.append(load_default_policy())
    return mode, unique_policies


# Convert merged config sections into one executable ScanJob; all schema validation happens here.
def build_job_from_sections(scan_config, export_config, logging_config, targets, report_config=None):
    scan_config = require_mapping(scan_config, "scan")
    export_config = require_mapping(export_config, "export")
    logging_config = require_mapping(logging_config, "logging")

    ports = parse_ports_config(scan_config.get("ports", "fast"))
    crypto = scan_config.get("crypto", "standard")
    if not isinstance(crypto, str) or crypto not in ["standard", "pqc"]:
        raise ConfigError("scan.crypto must be 'standard' or 'pqc'")

    resolve_dns = scan_config.get("resolve_dns", True)
    if not isinstance(resolve_dns, bool):
        raise ConfigError("scan.resolve_dns must be a boolean")
    workers = validate_workers(scan_config.get("workers", DEFAULT_WORKERS))

    export_filename = export_config.get("filename")
    if export_filename is not None and not isinstance(export_filename, str):
        raise ConfigError("export.filename must be a string")

    log_level = logging_config.get("level", "info")
    if not isinstance(log_level, str) or log_level not in LOG_LEVELS:
        raise ConfigError("logging.level must be one of: debug, error, info, warning")
    log_file = logging_config.get("file", DEFAULT_LOG_FILE)
    if log_file is not None and not isinstance(log_file, str):
        raise ConfigError("logging.file must be a string or null")

    report_config = report_config or {}
    report_name = report_config.get("name", "config")
    if report_name != "config":
        validate_config_name(report_name, "report.name")
    frequency = report_config.get("frequency", "manual")
    if not isinstance(frequency, str):
        raise ConfigError("report.frequency must be a string")

    export_directory = export_config.get("directory", DEFAULT_EXPORT_DIR)
    if not isinstance(export_directory, str):
        raise ConfigError("export.directory must be a string")
    filename_template = export_config.get("filename_template", "{timestamp}_{report_name}")
    if not isinstance(filename_template, str):
        raise ConfigError("export.filename_template must be a string")
    export_formats = export_config.get("formats", [])
    if isinstance(export_formats, str):
        export_formats = [export_formats]
    if not isinstance(export_formats, list) or not all(isinstance(item, str) for item in export_formats):
        raise ConfigError("export.formats must be a string or list of strings")
    invalid_formats = sorted(set(export_formats) - ALLOWED_EXPORT_FORMATS)
    if invalid_formats:
        raise ConfigError(f"export.formats contains unsupported formats: {', '.join(invalid_formats)}")

    return ScanJob(
        targets=",".join(targets),
        ports=ports,
        crypto=crypto,
        ip=not resolve_dns,
        csv_filename=export_filename,
        export_format=detect_export_format(export_filename),
        log_level=log_level,
        log_file=log_file,
        report_name=report_name,
        frequency=frequency,
        export_directory=export_directory,
        export_formats=tuple(export_formats),
        filename_template=filename_template,
        workers=workers,
    )


# Named reports inherit defaults, then override only the sections they define.
# Merge report-level settings over defaults before creating the executable ScanJob.
def build_config_scan_job(config, report_name=None):
    if "reports" in config:
        report = select_config_report(config, report_name)
        defaults = require_mapping(config.get("defaults", {}), "defaults")
        merged_scan = merge_mappings(defaults.get("scan", {}), report.get("scan", {}))
        merged_export = merge_mappings(defaults.get("export", {}), report.get("export", {}))
        merged_logging = merge_mappings(defaults.get("logging", {}), report.get("logging", {}))
        target_groups = load_report_targets(report)
        targets = [target for group in target_groups for target in group.targets]
        if not targets:
            raise ConfigError(f"report {report['name']} must define at least one target")
        policy_mode, policies = load_report_policies(report)
        job = build_job_from_sections(
            merged_scan,
            merged_export,
            merged_logging,
            targets,
            report,
        )
        job.target_groups = tuple(target_groups)
        job.policy_mode = policy_mode
        job.policies = tuple(policies)
        return job

    scan_config = require_mapping(config.get("scan", {}), "scan")
    if "targets" not in scan_config:
        raise ConfigError("scan.targets is required")
    targets = config_targets_to_list(scan_config["targets"], "scan.targets")
    job = build_job_from_sections(
        scan_config,
        config.get("export", {}),
        config.get("logging", {}),
        targets,
    )
    job.policies = (load_default_policy(),)
    return job


def load_cli_policies(args):
    policies = []
    policies.extend(load_named_policies(getattr(args, "policy_names", None)))
    for policy_file in getattr(args, "policy_files", None) or []:
        policies.append(load_policy_file(policy_file))
    if not policies:
        policies.append(load_default_policy())

    seen = set()
    unique_policies = []
    for policy in policies:
        if policy.name in seen:
            raise ConfigError(f"duplicate encryption policy in CLI arguments: {policy.name}")
        seen.add(policy.name)
        unique_policies.append(policy)
    return tuple(unique_policies)


def build_cli_scan_job(args):
    return ScanJob(
        targets=args.targets,
        ports=getattr(args, "ports", "fast"),
        crypto=getattr(args, "crypto", "standard"),
        ip=getattr(args, "ip", False),
        csv_filename=getattr(args, "csv_filename", None),
        export_format=getattr(args, "export_format", None),
        workers=getattr(args, "workers", DEFAULT_WORKERS),
        log_level=getattr(args, "log_level", "info"),
        log_file=(
            None
            if getattr(args, "no_log_file", False)
            else getattr(args, "log_file", DEFAULT_LOG_FILE)
        ),
        policies=load_cli_policies(args),
    )


def build_scan_job(args):
    config_path = getattr(args, "config", None)
    targets = getattr(args, "targets", None)
    if config_path is None and targets is not None:
        job = build_cli_scan_job(args)
    else:
        resolved_config_path = config_path or DEFAULT_CONFIG_FILE
        job = build_config_scan_job(
            load_yaml_config(resolved_config_path),
            getattr(args, "report", None),
        )

    if args.targets is not None:
        job.targets = args.targets
        job.target_groups = ()
    if getattr(args, "ports_was_explicit", False):
        job.ports = args.ports
    if getattr(args, "crypto_was_explicit", False):
        job.crypto = args.crypto
    if getattr(args, "workers_was_explicit", False):
        job.workers = args.workers
    if getattr(args, "ip_was_explicit", False):
        job.ip = args.ip
    if getattr(args, "export_was_explicit", False) or getattr(args, "csv_filename", None):
        job.csv_filename = args.csv_filename
        job.export_format = args.export_format
        job.export_formats = ()
    if getattr(args, "log_level_was_explicit", False):
        job.log_level = args.log_level
    if getattr(args, "log_file_was_explicit", False):
        job.log_file = args.log_file
    if getattr(args, "policy_was_explicit", False):
        job.policies = load_cli_policies(args)
        job.policy_mode = "strict_all"
    if getattr(args, "no_log_file", False):
        job.log_file = None
    job.dry_run = getattr(args, "dry_run", False)

    return job
