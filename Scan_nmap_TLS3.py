import argparse
import csv
import ipaddress
import json
import logging
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_CONFIG_FILE = "config/config.yaml"
DEFAULT_LOG_FILE = "logs/scan.log"
DEFAULT_EXPORT_DIR = "scan_reports"
DEFAULT_TARGETS_DIR = "config/targets_scan"
DEFAULT_POLICIES_DIR = "config/encryption_policy"
ALLOWED_EXPORT_FORMATS = {"csv", "cbom", "md"}
SAFE_CONFIG_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
MINIMUM_PQC_OPENSSL_VERSION = (3, 5, 0)
PQC_TLS_GROUPS = (
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
)
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

STARTUP_BANNER = """
████████╗██╗     ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
╚══██╔══╝██║     ██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
   ██║   ██║     ███████╗    ███████╗██║     ███████║██╔██╗ ██║
   ██║   ██║     ╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
   ██║   ███████╗███████║    ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═╝   ╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

╔════════════════════════════════════════════════════════════════╗
║  LCIT Cybersecurity                                           ║
║  TLS Recon | Crypto Inventory | CBOM | PQC Readiness          ║
║  Know your crypto surface.                                    ║
╚════════════════════════════════════════════════════════════════╝
""".strip()


class PQCPrerequisiteError(RuntimeError):
    pass


class ConfigError(RuntimeError):
    pass


@dataclass
class TargetGroup:
    name: str
    targets: tuple[str, ...]
    description: str = ""
    path: str = ""


@dataclass
class EncryptionPolicy:
    name: str
    version: str = ""
    description: str = ""
    path: str = ""


@dataclass
class ScanJob:
    targets: str
    ports: str
    crypto: str
    ip: bool
    csv_filename: str | None = None
    export_format: str | None = None
    pqc_groups: tuple[str, ...] = ()
    log_level: str = "info"
    log_file: str | None = DEFAULT_LOG_FILE
    scan_run_id: str = ""
    report_name: str = "manual"
    frequency: str = "manual"
    target_groups: tuple[TargetGroup, ...] = ()
    policies: tuple[EncryptionPolicy, ...] = ()
    policy_mode: str = "strict_all"
    export_directory: str = DEFAULT_EXPORT_DIR
    export_formats: tuple[str, ...] = ()
    filename_template: str = "{timestamp}_{report_name}"
    dry_run: bool = False


def print_startup_banner():
    print(STARTUP_BANNER)


# Command-line parsing and input normalization.
def parse_args():
    raw_args = sys.argv[1:]
    parser = argparse.ArgumentParser(
        description="Scan TLS configurations on one or more targets."
    )
    parser.add_argument(
        "--config",
        default=None,
        metavar="FILENAME",
        help=(
            f"load scan settings from this YAML file; if no target is provided, "
            f"{DEFAULT_CONFIG_FILE} is used"
        ),
    )
    parser.add_argument(
        "--report",
        metavar="NAME",
        help="run this report definition from the config file",
    )
    parser.add_argument(
        "--list-reports",
        action="store_true",
        help="list report definitions from the config file and exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate config and show the planned scan without running Nmap",
    )
    parser.add_argument(
        "-i",
        "--ip",
        action="store_true",
        help="disable DNS resolution and leave the FQDN column empty",
    )
    parser.add_argument(
        "-c",
        "--crypto",
        choices=["standard", "pqc"],
        default="standard",
        help="compliance criterion to use (default: standard)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="fast",
        type=parse_ports,
        help=(
            'TCP ports to test, for example "443,8443,9000-9010", '
            '"fast", or "all" (default: fast)'
        ),
    )
    parser.add_argument(
        "-e",
        "--export",
        dest="export_filename",
        metavar="FILENAME",
        help="export results to .csv, CycloneDX .cbom.json, or .md",
    )
    parser.add_argument(
        "--log-level",
        choices=sorted(LOG_LEVELS),
        default="info",
        help="log verbosity for scan diagnostics (default: info)",
    )
    parser.add_argument(
        "--log-file",
        default=DEFAULT_LOG_FILE,
        metavar="FILENAME",
        help=f"write scan diagnostics to this file (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--no-log-file",
        action="store_true",
        help="disable file logging for this run",
    )
    parser.add_argument(
        "targets",
        nargs="?",
        help="comma-separated FQDNs, IP addresses, or subnets",
    )
    parser.add_argument(
        "csv_filename",
        nargs="?",
        help="optional CSV output filename (legacy syntax)",
    )
    args = parser.parse_args()
    args.config_was_explicit = has_cli_option(raw_args, "--config")
    args.crypto_was_explicit = has_cli_option(raw_args, "-c", "--crypto")
    args.ports_was_explicit = has_cli_option(raw_args, "-p", "--ports")
    args.ip_was_explicit = has_cli_option(raw_args, "-i", "--ip")
    args.export_was_explicit = has_cli_option(raw_args, "-e", "--export")
    args.log_level_was_explicit = has_cli_option(raw_args, "--log-level")
    args.log_file_was_explicit = has_cli_option(raw_args, "--log-file")
    args.report_was_explicit = has_cli_option(raw_args, "--report")

    explicit_export = args.export_filename
    if explicit_export and args.csv_filename:
        parser.error("use either --export or the positional CSV filename, not both")
    if explicit_export:
        args.csv_filename = explicit_export

    args.export_format = None
    if args.csv_filename:
        lower_filename = args.csv_filename.lower()
        if lower_filename.endswith(".cbom.json"):
            args.export_format = "cbom"
        elif lower_filename.endswith(".md"):
            args.export_format = "md"
        elif lower_filename.endswith(".csv") or not explicit_export:
            args.export_format = "csv"
        else:
            parser.error("--export filename must end with .csv, .cbom.json, or .md")
    return args


def has_cli_option(raw_args, *names):
    for value in raw_args:
        if value in names:
            return True
        if any(value.startswith(f"{name}=") for name in names if name.startswith("--")):
            return True
    return False


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
    for key in ("allowed_versions", "allowed_cipher_algorithms", "allowed_signature_hashes"):
        values = tls_config.get(key)
        if not isinstance(values, list) or not values or not all(isinstance(value, str) for value in values):
            raise ConfigError(f"policy {name}.tls.{key} must be a non-empty list of strings")
    minimum_rsa_bits = tls_config.get("minimum_rsa_bits")
    if not isinstance(minimum_rsa_bits, int) or minimum_rsa_bits < 1:
        raise ConfigError(f"policy {name}.tls.minimum_rsa_bits must be a positive integer")
    return EncryptionPolicy(name=name, version=version, description=description, path=str(policy_file))


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
    return mode, unique_policies


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
    )


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
    return build_job_from_sections(
        scan_config,
        config.get("export", {}),
        config.get("logging", {}),
        targets,
    )


def build_cli_scan_job(args):
    return ScanJob(
        targets=args.targets,
        ports=getattr(args, "ports", "fast"),
        crypto=getattr(args, "crypto", "standard"),
        ip=getattr(args, "ip", False),
        csv_filename=getattr(args, "csv_filename", None),
        export_format=getattr(args, "export_format", None),
        log_level=getattr(args, "log_level", "info"),
        log_file=(
            None
            if getattr(args, "no_log_file", False)
            else getattr(args, "log_file", DEFAULT_LOG_FILE)
        ),
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
    if getattr(args, "no_log_file", False):
        job.log_file = None
    job.dry_run = getattr(args, "dry_run", False)

    return job


def configure_logging(job):
    logger = logging.getLogger("tls_scan")
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()
    logger.setLevel(LOG_LEVELS[job.log_level])
    logger.propagate = False

    if job.log_file is None:
        logger.addHandler(logging.NullHandler())
        return logging.LoggerAdapter(logger, {"scan_run_id": job.scan_run_id})

    log_path = Path(job.log_file)
    if log_path.parent != Path("."):
        log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(LOG_LEVELS[job.log_level])
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s run_id=%(scan_run_id)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logging.LoggerAdapter(logger, {"scan_run_id": job.scan_run_id})


def parse_openssl_version(version_output):
    match = re.search(r"\bOpenSSL\s+(\d+)\.(\d+)\.(\d+)", version_output)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def check_pqc_prerequisites():
    if shutil.which("openssl") is None:
        raise PQCPrerequisiteError(
            "PQC preflight check failed.\n\n"
            "OpenSSL 3.5 or later is required for PQC scans.\n"
            "Detected version: OpenSSL not found\n\n"
            "Please install OpenSSL 3.5 or later and ensure that TLS ML-KEM "
            "groups,\nincluding X25519MLKEM768, are available."
        )

    try:
        version_result = subprocess.run(
            ["openssl", "version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PQCPrerequisiteError(
            "PQC preflight check failed: unable to execute OpenSSL."
        ) from error

    version_text = (version_result.stdout or version_result.stderr).strip()
    version = parse_openssl_version(version_text)
    if version_result.returncode != 0 or version is None:
        raise PQCPrerequisiteError(
            "PQC preflight check failed.\n\n"
            "OpenSSL 3.5 or later is required for PQC scans.\n"
            f"Detected version: {version_text or 'unknown'}"
        )

    if version < MINIMUM_PQC_OPENSSL_VERSION:
        raise PQCPrerequisiteError(
            "PQC preflight check failed.\n\n"
            "OpenSSL 3.5 or later is required for PQC scans.\n"
            f"Detected version: {version_text}\n\n"
            "Please upgrade OpenSSL and ensure that TLS ML-KEM groups,\n"
            "including X25519MLKEM768, are available."
        )

    try:
        groups_result = subprocess.run(
            ["openssl", "list", "-tls-groups"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PQCPrerequisiteError(
            "PQC preflight check failed: unable to list OpenSSL TLS groups."
        ) from error

    groups_output = f"{groups_result.stdout}\n{groups_result.stderr}"
    available_groups = [
        group for group in PQC_TLS_GROUPS if group.lower() in groups_output.lower()
    ]
    if groups_result.returncode != 0 or not available_groups:
        raise PQCPrerequisiteError(
            "PQC preflight check failed.\n\n"
            "OpenSSL 3.5 or later with TLS ML-KEM support is required for "
            "PQC scans.\n"
            f"Detected version: {version_text}\n"
            "Required TLS group: X25519MLKEM768\n\n"
            "Please ensure that the required TLS ML-KEM groups are available."
        )

    return version_text, available_groups


def parse_ports(value):
    value = value.strip().lower()
    if value in ["fast", "all"]:
        return value

    ports = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            raise argparse.ArgumentTypeError("port entries cannot be empty")

        if "-" in item:
            bounds = item.split("-")
            if len(bounds) != 2 or not all(bound.isdigit() for bound in bounds):
                raise argparse.ArgumentTypeError(f"invalid port range: {item}")
            start, end = (int(bound) for bound in bounds)
            if start > end:
                raise argparse.ArgumentTypeError(f"invalid port range: {item}")
            if start < 1 or end > 65535:
                raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
        elif not item.isdigit() or not 1 <= int(item) <= 65535:
            raise argparse.ArgumentTypeError("ports must be between 1 and 65535")

        ports.append(item)

    return ",".join(ports)


def normalize_targets(targets):
    normalized_targets = [target.strip() for target in targets.split(",")]
    return " ".join(target for target in normalized_targets if target)


# DNS and certificate metadata extraction.
def resolve_fqdn(ip_address):
    try:
        fqdn = socket.gethostbyaddr(ip_address)[0].rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return ""
    return fqdn if fqdn != ip_address else ""


def resolve_target_fqdns(targets):
    fqdn_cache = {}
    for target in normalize_targets(targets).split():
        try:
            ipaddress.ip_network(target, strict=False)
            continue
        except ValueError:
            pass

        try:
            ipaddress.ip_address(target)
            continue
        except ValueError:
            pass

        try:
            canonical_name, _, addresses = socket.gethostbyname_ex(target)
        except (socket.gaierror, OSError):
            continue

        fqdn = canonical_name.rstrip(".") if canonical_name else target.rstrip(".")
        for address in addresses:
            fqdn_cache.setdefault(address, fqdn)

    return fqdn_cache


def extract_public_key(certificate_output):
    key_type_match = re.search(
        r"Public Key type:\s*([^\s]+)",
        certificate_output,
        re.IGNORECASE,
    )
    key_bits_match = re.search(
        r"Public Key bits:\s*(\d+)",
        certificate_output,
        re.IGNORECASE,
    )

    if not key_type_match:
        return "Unknown", None

    key_type = key_type_match.group(1).upper()
    key_bits = int(key_bits_match.group(1)) if key_bits_match else None
    return key_type, key_bits


def extract_signature_algorithm(certificate_output):
    signature_match = re.search(
        r"Signature Algorithm:\s*([^\s]+)",
        certificate_output,
        re.IGNORECASE,
    )
    return signature_match.group(1) if signature_match else ""


def format_openssl_endpoint(host, port):
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def probe_pqc_key_exchange(host, port, server_name, groups=PQC_TLS_GROUPS):
    endpoint = format_openssl_endpoint(host, port)
    for group in groups:
        command = [
            "openssl",
            "s_client",
            "-connect",
            endpoint,
            "-tls1_3",
            "-groups",
            group,
            "-brief",
        ]
        if server_name:
            command.extend(["-servername", server_name])

        try:
            result = subprocess.run(
                command,
                input="",
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue

        output = f"{result.stdout}\n{result.stderr}"
        negotiated_tls_1_3 = re.search(
            r"Protocol(?: version)?\s*:\s*TLSv1\.3",
            output,
            re.IGNORECASE,
        )
        if (
            result.returncode == 0
            and negotiated_tls_1_3
            and group.lower() in output.lower()
        ):
            return group

    return "Not supported"


def evaluate_pqc_compliance(tls_version, key_exchange):
    if tls_version != "TLSv1.3":
        return "KO", "TLS 1.3 required"
    if key_exchange in PQC_TLS_GROUPS:
        return "OK", ""
    return "KO", "No supported PQC group"


# Cipher-suite parsing and per-row compliance evaluation.
def is_cipher_suite_compliant(tls_version, cipher_suite):
    cipher_suite = cipher_suite.upper()
    cipher_tokens = cipher_suite.split("_")

    if any(
        weak_token in cipher_tokens
        for weak_token in ["NULL", "EXPORT", "RC4", "DES", "3DES", "IDEA"]
    ):
        return False

    if "MD5" in cipher_tokens or "SHA1" in cipher_tokens:
        return False

    if cipher_suite.endswith("_SHA"):
        return False

    accepted_encryption = any(
        algorithm in cipher_suite
        for algorithm in ["_GCM_", "_CCM_", "CHACHA20_POLY1305"]
    ) or cipher_suite.endswith(("_GCM", "_CCM"))
    accepted_encryption = accepted_encryption or "_CBC_" in cipher_suite
    if not accepted_encryption:
        return False

    if tls_version == "TLSv1.3":
        return True

    return cipher_suite.startswith(("TLS_ECDHE_", "TLS_DHE_", "TLS_RSA_"))


def extract_cipher_suites(cipher_output):
    cipher_suites = []
    tls_version = "N/A"

    for line in cipher_output.splitlines():
        stripped_line = line.strip()
        if stripped_line.startswith("TLSv"):
            tls_version = stripped_line.split(":")[0]
        elif stripped_line.startswith("TLS_"):
            cipher_suites.append((tls_version, stripped_line.split()[0]))

    return cipher_suites


def check_compliance(
    tls_version,
    cipher_suite,
    cert_validity,
    certificate_output,
    public_key_type,
    public_key_bits,
):
    compliance, _ = evaluate_compliance(
        tls_version,
        cipher_suite,
        cert_validity,
        certificate_output,
        public_key_type,
        public_key_bits,
    )
    return compliance


def evaluate_compliance(
    tls_version,
    cipher_suite,
    cert_validity,
    certificate_output,
    public_key_type,
    public_key_bits,
):
    signature_algorithm = extract_signature_algorithm(certificate_output)
    security_details = f"{cipher_suite} {signature_algorithm}".upper()
    normalized_details = security_details.replace("-", "").replace("_", "")
    cipher_tokens = cipher_suite.upper().split("_")

    if "MD5" in normalized_details:
        return "KO", "MD5"

    if "SHA1" in normalized_details or cipher_suite.upper().endswith("_SHA"):
        return "KO", "SHA-1"

    if tls_version not in ["TLSv1.2", "TLSv1.3"]:
        return "KO", "TLS version"

    if any(
        token in cipher_tokens
        for token in ["NULL", "EXPORT", "RC4", "DES", "3DES", "IDEA"]
    ):
        return "KO", "Weak cipher"

    if not is_cipher_suite_compliant(tls_version, cipher_suite):
        return "KO", "Cipher suite"

    if public_key_type == "RSA" and (
        public_key_bits is None or public_key_bits < 2048
    ):
        return "KO", "RSA key size"

    try:
        cert_expiry_date = datetime.strptime(cert_validity, "%Y-%m-%d")
    except ValueError:
        return "KO", "Certificate date"

    if cert_expiry_date < datetime.now():
        return "KO", "Certificate expired"

    return "OK", ""


# Endpoint grading is separate from compliance and uses the weakest finding.
def grade_finding(finding):
    tls_version = finding["tls_version"]
    cipher_suite = finding["cipher_suite"].upper()
    cipher_tokens = cipher_suite.split("_")
    signature_algorithm = extract_signature_algorithm(
        finding["certificate_output"]
    ).upper()
    normalized_signature = signature_algorithm.replace("-", "").replace("_", "")
    public_key_type = finding["public_key_type"]
    public_key_bits = finding["public_key_bits"]

    try:
        cert_expiry_date = datetime.strptime(
            finding["cert_validity"],
            "%Y-%m-%d",
        )
    except ValueError:
        return "F"

    if cert_expiry_date < datetime.now():
        return "F"

    if any(token in cipher_tokens for token in ["NULL", "EXPORT", "RC4"]):
        return "F"

    if tls_version not in ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
        return "F"

    if public_key_type == "RSA" and (
        public_key_bits is None or public_key_bits < 2048
    ):
        return "F"

    if "MD5" in cipher_tokens or "MD5" in normalized_signature:
        return "D"

    if tls_version == "TLSv1.0" or any(
        token in cipher_tokens for token in ["DES", "3DES", "IDEA"]
    ):
        return "D"

    if (
        tls_version == "TLSv1.1"
        or "SHA1" in cipher_tokens
        or cipher_suite.endswith("_SHA")
        or "SHA1" in normalized_signature
    ):
        return "C"

    if public_key_type == "RSA" and public_key_bits < 3072:
        return "B"

    if tls_version == "TLSv1.2" and cipher_suite.startswith("TLS_RSA_"):
        return "B"

    if "_CBC_" in cipher_suite:
        return "A"

    return "A+"


def calculate_host_grade(findings):
    grade_order = {"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "F": 5}
    grades = [grade_finding(finding) for finding in findings]
    if not grades:
        return "F"

    worst_grade = max(grades, key=grade_order.get)
    has_tls_1_3 = any(
        finding["tls_version"] == "TLSv1.3" for finding in findings
    )
    if worst_grade == "A+" and not has_tls_1_3:
        return "A"
    return worst_grade


def apply_endpoint_grades(results, findings):
    endpoint_grades = {
        endpoint: calculate_host_grade(endpoint_findings)
        for endpoint, endpoint_findings in findings.items()
    }
    for row in results:
        # A grade belongs to one IP and port, not to the whole host.
        row.insert(3, endpoint_grades[(row[0], row[2])])


# Runtime dependencies are loaded after argument parsing to keep --help usable.
def load_dependencies():
    try:
        import nmap
        from prettytable import PrettyTable
        from tqdm import tqdm
    except ImportError:
        print(
            "Missing dependency. Run: "
            "python3 -m pip install python-nmap prettytable tqdm"
        )
        sys.exit(1)
    return nmap, PrettyTable, tqdm


def run_scan_with_progress(scanner, tqdm, description, **scan_options):
    scan_error = []

    def run_scan():
        try:
            scanner.scan(**scan_options)
        except Exception as error:
            scan_error.append(error)

    # python-nmap blocks until completion, so a worker thread keeps tqdm active.
    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()

    # Nmap does not expose a reliable percentage here; show elapsed activity.
    progress = tqdm(
        total=None,
        desc=description,
        unit="step",
        bar_format="{desc}: {elapsed} [{bar:20}]",
    )
    while scan_thread.is_alive():
        progress.update(1)
        scan_thread.join(timeout=0.2)
    progress.close()

    if scan_error:
        raise scan_error[0]


def discover_open_tcp_ports(nmap, tqdm, targets, mode):
    scanner = nmap.PortScanner()
    scan_options = {
        "fast": {
            "arguments": "-F -T4 --open --max-retries 1",
        },
        "all": {
            "ports": "1-65535",
            "arguments": "-T4 --open --max-retries 1",
        },
    }
    run_scan_with_progress(
        scanner,
        tqdm,
        "TCP discovery",
        hosts=targets,
        **scan_options[mode],
    )

    open_ports = {}
    for host in scanner.all_hosts():
        if "tcp" not in scanner[host]:
            continue
        ports = [
            port
            for port, port_info in scanner[host]["tcp"].items()
            if port_info.get("state") == "open"
        ]
        if ports:
            open_ports[host] = sorted(ports)
    return open_ports


# Transform raw Nmap script output into table/CSV rows and grading findings.
def collect_scan_results(scanner, args, results, findings, fqdn_cache):
    for host in scanner.all_hosts():
        if "tcp" not in scanner[host]:
            continue

        fqdn = fqdn_cache.setdefault(
            host,
            "" if args.ip else resolve_fqdn(host),
        )
        for port, port_info in scanner[host]["tcp"].items():
            if port_info.get("state") != "open" or "script" not in port_info:
                continue

            certificate_output = port_info["script"].get("ssl-cert", "")
            public_key_type, public_key_bits = extract_public_key(
                certificate_output
            )
            public_key = public_key_type
            if public_key_bits is not None:
                public_key = f"{public_key_type} {public_key_bits} bits"

            cert_validity = "N/A"
            if "Not valid after:" in certificate_output:
                start = certificate_output.find("Not valid after:") + len(
                    "Not valid after:"
                )
                end = certificate_output.find("T", start)
                cert_validity = certificate_output[start:end].strip()

            cipher_output = port_info["script"].get("ssl-enum-ciphers", "")
            cipher_suites = extract_cipher_suites(cipher_output)
            key_exchange = None
            if args.crypto == "pqc" and cipher_suites:
                key_exchange = probe_pqc_key_exchange(
                    host,
                    port,
                    fqdn,
                    args.pqc_groups,
                )

            for tls_version, cipher_suite in cipher_suites:
                if args.crypto == "pqc":
                    compliance, reason = evaluate_pqc_compliance(
                        tls_version,
                        key_exchange,
                    )
                else:
                    compliance, reason = evaluate_compliance(
                        tls_version,
                        cipher_suite,
                        cert_validity,
                        certificate_output,
                        public_key_type,
                        public_key_bits,
                    )
                finding = {
                    "tls_version": tls_version,
                    "cipher_suite": cipher_suite,
                    "cert_validity": cert_validity,
                    "certificate_output": certificate_output,
                    "public_key_type": public_key_type,
                    "public_key_bits": public_key_bits,
                }
                findings.setdefault((host, port), []).append(finding)
                row = [
                    host,
                    fqdn,
                    port,
                    tls_version,
                    cipher_suite,
                    public_key,
                    cert_validity,
                ]
                if args.crypto == "pqc":
                    row.append(key_exchange)
                row.extend([compliance, reason])
                results.append(row)


def build_csv_export(results, args, scan_timestamp):
    headers = [
        "IP",
        "FQDN",
        "Port",
        "TLS Grade" if args.crypto == "pqc" else "Grade",
        "TLS Version",
        "Cipher Suite",
        "Public Key",
        "Certificate Validity",
    ]
    if args.crypto == "pqc":
        headers.append("Key Exchange")
    headers.extend(
        [
            "Compliance",
            "Reason",
            "Scan Timestamp",
            "Scan Targets",
            "Port Selection",
            "Crypto Profile",
            "DNS Resolution",
        ]
    )

    scan_metadata = [
        scan_timestamp,
        args.targets,
        str(args.ports),
        args.crypto,
        "disabled" if args.ip else "enabled",
    ]
    rows = [list(row) + scan_metadata for row in results]
    return headers, rows


def local_report_timestamp():
    return datetime.now().strftime("%Y-%m-%d-%H%M%S")


def local_scan_timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def export_extension(export_format):
    if export_format == "cbom":
        return ".cbom.json"
    if export_format == "md":
        return ".md"
    if export_format == "csv":
        return ".csv"
    raise ConfigError(f"unsupported export format: {export_format}")


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


def write_exports(results, job, scan_timestamp, export_paths):
    written_files = []
    for export_format, export_path in export_paths.items():
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
        else:
            csv_headers, csv_rows = build_csv_export(results, job, scan_timestamp)
            with export_path.open("w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(csv_headers)
                writer.writerows(csv_rows)
        written_files.append(str(export_path))
    return written_files


def print_dry_run(job, export_paths):
    print(f"Report: {job.report_name}")
    print(f"Frequency: {job.frequency}")
    print(f"Targets: {job.targets}")
    if job.target_groups:
        print("Target groups:")
        for group in job.target_groups:
            print(f"- {group.name} ({len(group.targets)} targets)")
    print(f"Ports: {job.ports}")
    print(f"Crypto profile: {job.crypto}")
    print(f"DNS resolution: {'disabled' if job.ip else 'enabled'}")
    print(f"Log level: {job.log_level}")
    print(f"Log file: {job.log_file or 'disabled'}")
    if job.policies:
        print(f"Policy mode: {job.policy_mode}")
        print("Policies:")
        for policy in job.policies:
            version = f" v{policy.version}" if policy.version else ""
            print(f"- {policy.name}{version}")
    if export_paths:
        print("Would write:")
        for path in export_paths.values():
            print(f"- {path}")


def build_cbom(results, pqc=False):
    components = []
    algorithm_refs = {}
    public_key_refs = {}

    def make_ref(value):
        return "crypto:" + str(uuid.uuid5(uuid.NAMESPACE_URL, value))

    def add_algorithm(name, primitive):
        key = (name, primitive)
        if key not in algorithm_refs:
            algorithm_ref = make_ref(f"algorithm:{name}:{primitive}")
            algorithm_refs[key] = algorithm_ref
            components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": algorithm_ref,
                    "name": name,
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {"primitive": primitive},
                    },
                }
            )
        return algorithm_refs[key]

    primitive_by_key_type = {
        "RSA": "pke",
        "ECDSA": "signature",
        "ED25519": "signature",
        "DSA": "signature",
        "ECDH": "key-agree",
    }

    for row in results:
        host, fqdn, port, grade, tls_version, cipher_suite = row[:6]
        public_key, cert_validity = row[6:8]
        key_exchange = row[8] if pqc else None
        compliance_index = 9 if pqc else 8
        compliance = row[compliance_index]
        reason = row[compliance_index + 1]

        crypto_refs = []
        key_match = re.fullmatch(r"(.+?)(?: (\d+) bits)?", public_key)
        if key_match and key_match.group(1) != "Unknown":
            key_type = key_match.group(1)
            key_size = (
                int(key_match.group(2)) if key_match.group(2) is not None else None
            )
            algorithm_ref = add_algorithm(
                key_type,
                primitive_by_key_type.get(key_type, "unknown"),
            )
            public_key_id = (host, port, key_type, key_size)
            if public_key_id not in public_key_refs:
                public_key_ref = make_ref(
                    f"public-key:{host}:{port}:{key_type}:{key_size}"
                )
                public_key_refs[public_key_id] = public_key_ref
                material_properties = {
                    "type": "public-key",
                    "algorithmRef": algorithm_ref,
                }
                if key_size is not None:
                    material_properties["size"] = key_size
                components.append(
                    {
                        "type": "cryptographic-asset",
                        "bom-ref": public_key_ref,
                        "name": f"{key_type} public key on {host}:{port}",
                        "cryptoProperties": {
                            "assetType": "related-crypto-material",
                            "relatedCryptoMaterialProperties": material_properties,
                        },
                    }
                )
            crypto_refs.append(public_key_refs[public_key_id])

        if key_exchange in PQC_TLS_GROUPS:
            upper_exchange = key_exchange.upper()
            primitive = (
                "combiner"
                if "MLKEM" in upper_exchange and "X25519" in upper_exchange
                else "kem"
                if "MLKEM" in upper_exchange
                else "key-agree"
            )
            crypto_refs.append(add_algorithm(key_exchange, primitive))

        properties = [
            {"name": "scan-tls:ip", "value": str(host)},
            {"name": "scan-tls:port", "value": str(port)},
            {"name": "scan-tls:grade", "value": str(grade)},
            {"name": "scan-tls:compliance", "value": str(compliance)},
            {
                "name": "scan-tls:certificate-valid-until",
                "value": str(cert_validity),
            },
        ]
        if fqdn:
            properties.append({"name": "scan-tls:fqdn", "value": str(fqdn)})
        if reason:
            properties.append({"name": "scan-tls:reason", "value": str(reason)})
        if key_exchange:
            properties.append(
                {"name": "scan-tls:key-exchange", "value": str(key_exchange)}
            )

        protocol_properties = {
            "type": "tls",
            "version": tls_version.removeprefix("TLSv"),
            "cipherSuites": [{"name": cipher_suite}],
        }
        if crypto_refs:
            protocol_properties["cryptoRefArray"] = crypto_refs

        protocol_ref = make_ref(
            f"tls:{host}:{port}:{tls_version}:{cipher_suite}"
        )
        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": protocol_ref,
                "name": f"{tls_version} {cipher_suite} on {host}:{port}",
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": protocol_properties,
                },
                "properties": properties,
            }
        )

    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "lifecycles": [{"phase": "discovery"}],
        },
        "components": components,
    }


def main():
    cli_args = parse_args()
    try:
        if getattr(cli_args, "list_reports", False):
            config_path = cli_args.config or DEFAULT_CONFIG_FILE
            for report_name in list_config_reports(load_yaml_config(config_path)):
                print(report_name)
            return 0
        job = build_scan_job(cli_args)
    except ConfigError as error:
        print(error, file=sys.stderr)
        return 1

    job.scan_run_id = str(uuid.uuid4())
    scan_start = time.monotonic()
    try:
        logger = configure_logging(job)
    except OSError as error:
        print(f"Unable to configure logging: {error}", file=sys.stderr)
        return 1

    scan_timestamp = local_scan_timestamp()
    report_timestamp = local_report_timestamp()
    try:
        export_paths = build_export_paths(job, report_timestamp)
    except ConfigError as error:
        print(error, file=sys.stderr)
        return 1

    if job.dry_run:
        print_dry_run(job, export_paths)
        return 0
    print_startup_banner()
    targets = normalize_targets(job.targets)
    logger.info(
        "scan_start targets=%s ports=%s crypto=%s dns=%s log_level=%s log_file=%s export=%s",
        targets,
        job.ports,
        job.crypto,
        "disabled" if job.ip else "enabled",
        job.log_level,
        job.log_file or "disabled",
        job.csv_filename or "none",
    )
    if not targets:
        logger.error("scan_failed reason=missing_targets")
        print("At least one target is required.")
        return 1

    if job.crypto == "pqc":
        try:
            openssl_version, job.pqc_groups = check_pqc_prerequisites()
        except PQCPrerequisiteError as error:
            logger.error("pqc_preflight_failed error=%s", error)
            print(error, file=sys.stderr)
            return 2
        logger.info(
            "pqc_preflight_passed openssl_version=%s groups=%s",
            openssl_version,
            ",".join(job.pqc_groups),
        )
        print(f"PQC preflight check passed: {openssl_version}")
        print("Compliance criterion: POST-QUANTUM")

    nmap, PrettyTable, tqdm = load_dependencies()
    logger.info("dependencies_loaded")
    print("Initializing TLS information scan...")
    results = []
    findings = {}
    fqdn_cache = resolve_target_fqdns(targets)
    logger.debug("fqdn_cache_entries=%s", len(fqdn_cache))
    tls_arguments = (
        "-sV --version-light --script ssl-cert,ssl-enum-ciphers"
    )
    logger.debug("tls_scan_arguments=%s", tls_arguments)

    # Discovery modes first identify open ports, then run TLS scripts on them.
    if job.ports in ["fast", "all"]:
        scan_label = "common" if job.ports == "fast" else "all"
        logger.info("port_discovery_start mode=%s targets=%s", job.ports, targets)
        print(f"Discovering open TCP ports ({scan_label} ports)...")
        open_ports = discover_open_tcp_ports(
            nmap,
            tqdm,
            targets,
            job.ports,
        )
        discovered_count = sum(len(ports) for ports in open_ports.values())
        logger.info(
            "port_discovery_done hosts=%s open_ports=%s",
            len(open_ports),
            discovered_count,
        )
        progress = tqdm(total=len(open_ports), desc="Scanning hosts")
        for host, ports in open_ports.items():
            scanner = nmap.PortScanner()
            logger.info(
                "tls_scan_start host=%s ports=%s",
                host,
                ",".join(str(port) for port in ports),
            )
            run_scan_with_progress(
                scanner,
                tqdm,
                f"TLS scan {host}",
                hosts=host,
                ports=",".join(str(port) for port in ports),
                arguments=tls_arguments,
            )
            collect_scan_results(
                scanner,
                job,
                results,
                findings,
                fqdn_cache,
            )
            logger.info("tls_scan_done host=%s", host)
            progress.update(1)
        progress.close()
    else:
        scanner = nmap.PortScanner()
        logger.info("tls_scan_start targets=%s ports=%s", targets, job.ports)
        run_scan_with_progress(
            scanner,
            tqdm,
            "TLS scan",
            hosts=targets,
            ports=job.ports,
            arguments=tls_arguments,
        )
        collect_scan_results(
            scanner,
            job,
            results,
            findings,
            fqdn_cache,
        )
        logger.info("tls_scan_done targets=%s ports=%s", targets, job.ports)

    apply_endpoint_grades(results, findings)
    logger.info("scan_results endpoints=%s rows=%s", len(findings), len(results))

    if not results:
        logger.warning("no_tls_service_found ports=%s", job.ports)
        print(
            "\nNo TLS service found on the selected ports. "
            "Use -p fast, -p all, or specify ports with -p."
        )

    headers = [
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
        headers.append("Key Exchange")
    headers.append("Compliance")

    table = PrettyTable(headers)
    for row in results:
        # The last value is the CSV-only reason and is hidden in the terminal.
        table.add_row(row[:-1])
    print("\n" + str(table))

    if export_paths:
        written_files = write_exports(results, job, scan_timestamp, export_paths)
        for export_format, export_path in export_paths.items():
            logger.info(
                "export_written file=%s format=%s rows=%s",
                export_path,
                export_format,
                len(results),
            )
        print("\nResults have been saved to:")
        for written_file in written_files:
            print(f"- {written_file}")

    duration_seconds = time.monotonic() - scan_start
    logger.info("scan_end status=success duration_seconds=%.3f", duration_seconds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
