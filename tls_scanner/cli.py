"""
Command-line interface and top-level TLS scan orchestration.

Called by:
- `Scan_nmap_TLS3.py`, which remains the root entry point;
- CLI tests that validate parsing, dry-run behavior, and the main execution flow.

Produces:
- a CLI return code;
- readable terminal output;
- optional exports through `tls_scanner.exports` modules.
"""

import argparse
import sys
import time
import uuid

from .config import (
    build_cli_scan_job,
    build_config_scan_job,
    build_scan_job,
    list_config_reports,
    load_yaml_config,
)
from .constants import DEFAULT_CONFIG_FILE, DEFAULT_LOG_FILE, LOG_LEVELS
from .crypto_policy import apply_endpoint_grades
from .exports.paths import build_export_paths, local_report_timestamp, local_scan_timestamp, write_exports
from .logging_config import configure_logging
from .models import ConfigError, PQCPrerequisiteError
from .network import normalize_targets, parse_ports, resolve_target_fqdns
from .pqc import check_pqc_prerequisites
from .scanner import collect_scan_results, discover_open_tcp_ports, load_dependencies, run_scan_with_progress


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



def has_cli_option(raw_args, *names):
    for value in raw_args:
        if value in names:
            return True
        if any(value.startswith(f"{name}=") for name in names if name.startswith("--")):
            return True
    return False


def print_startup_banner():
    print(STARTUP_BANNER)


# Parse CLI flags first, then record which values were explicit so they can override YAML config.
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
        "--policy",
        dest="policy_names",
        action="append",
        metavar="NAME",
        help="named encryption policy to enforce; repeat to require multiple policies",
    )
    parser.add_argument(
        "--policy-file",
        dest="policy_files",
        action="append",
        metavar="FILENAME",
        help="YAML encryption policy file to enforce; repeat to require multiple policies",
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
    args.policy_was_explicit = has_cli_option(raw_args, "--policy", "--policy-file")

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


# Main deliberately stays as orchestration: build job, run scan, grade, display, export.
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
