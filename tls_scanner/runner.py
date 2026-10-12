"""
Headless execution interface of the scan engine.

Called by:
- `tls_scanner.cli.run_job`, which shares `collect_job_results` so the CLI and the WebUI worker
  run exactly the same scan code;
- the WebUI worker (`backend/src/tls_scan_app/workers`), through `execute_scan`.

Produces:
- `ScanOutcome`: result rows, endpoint findings, written files, the structured report model,
  and which targets were (not) processed.

Unlike `cli.run_job`, nothing is printed and nothing calls `sys.exit`: errors are raised, and
cancellation is cooperative through a `threading.Event`.
"""

import ipaddress
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .checks.identity import resolve_requested_names
from .crypto_policy import apply_endpoint_grades
from .exports.paths import build_export_paths, local_report_timestamp, local_scan_timestamp, write_exports
from .exports.report_model import build_report_model, report_model_to_dict
from .logging_config import configure_logging
from .models import ConfigError, PQCPrerequisiteError, ScanJob
from .network import normalize_targets, resolve_target_fqdns
from .pqc import check_pqc_prerequisites
from .scanner import collect_scan_results, discover_open_tcp_ports, run_scan_with_progress, scan_tls_hosts_parallel

TLS_ARGUMENTS = "-sV --version-light --script ssl-cert,ssl-enum-ciphers"

_FQDN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$")
_PORTS_RE = re.compile(r"^[0-9]{1,5}([-,][0-9]{1,5})*$")


class QuietProgress:
    """Drop-in replacement for tqdm that prints nothing (the worker has no terminal)."""

    def __init__(self, *args, **kwargs):
        pass

    def update(self, *args, **kwargs):
        pass

    def close(self):
        pass


def validate_scan_input(job: ScanJob, max_targets: int = 4096) -> None:
    """Strict whitelist of what may reach nmap's command line.

    python-nmap splits its arguments with shlex, so a target such as `-oN /x` would become an
    nmap option. Only FQDN, IPv4/IPv6 and CIDR tokens, and fast/all/port-list specs, are accepted.
    """
    targets = normalize_targets(job.targets).split()
    if not targets:
        raise ConfigError("at least one target is required")
    if len(targets) > max_targets:
        raise ConfigError(f"too many targets ({len(targets)} > {max_targets})")
    for target in targets:
        if target.startswith("-"):
            raise ConfigError(f"invalid target: {target!r}")
        try:
            ipaddress.ip_network(target, strict=False)
            continue
        except ValueError:
            pass
        if not _FQDN_RE.match(target):
            raise ConfigError(f"invalid target: {target!r}")
    if job.ports not in ("fast", "all") and not _PORTS_RE.match(job.ports):
        raise ConfigError(f"invalid ports: {job.ports!r}")


@dataclass
class ScanOutcome:
    status: str  # "completed" | "cancelled"
    results: list[list[Any]] = field(default_factory=list)
    findings: dict[str, Any] = field(default_factory=dict)
    written_files: list[str] = field(default_factory=list)
    report_model: dict[str, Any] | None = None
    scanned_hosts: list[str] = field(default_factory=list)
    skipped_hosts: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


Hook = Callable[[str, dict[str, Any]], None]


def collect_job_results(job, targets, logger, nmap, tqdm, cancel_event=None, on_event: Hook | None = None, on_host_done=None):
    """Discovery + TLS scan + grading; shared by the CLI and the worker. Returns (results, findings)."""
    emit = on_event or (lambda name, data: None)
    results = []
    findings = {}
    fqdn_cache = resolve_target_fqdns(targets)
    logger.debug("fqdn_cache_entries=%s", len(fqdn_cache))
    if "hostname_san" in job.tls_checks:
        # names the user actually asked for (never a PTR), used as reference identity by the SAN check
        job.tls_check_requested_names.update(resolve_requested_names(targets))
    logger.debug("tls_scan_arguments=%s", TLS_ARGUMENTS)

    if job.ports in ["fast", "all"]:
        logger.info("port_discovery_start mode=%s targets=%s", job.ports, targets)
        emit("phase", {"phase": "discovery"})
        open_ports = discover_open_tcp_ports(nmap, tqdm, targets, job.ports)
        discovered_count = sum(len(ports) for ports in open_ports.values())
        logger.info("port_discovery_done hosts=%s open_ports=%s", len(open_ports), discovered_count)
        emit("phase", {"phase": "tls_scan", "hosts": sorted(open_ports)})
        extra = {}
        if cancel_event is not None or on_host_done is not None:
            extra = {"cancel_event": cancel_event, "on_host_done": on_host_done}
        results, findings = scan_tls_hosts_parallel(nmap, tqdm, open_ports, job, fqdn_cache, TLS_ARGUMENTS, logger, **extra)
    else:
        scanner = nmap.PortScanner()
        logger.info("tls_scan_start targets=%s ports=%s", targets, job.ports)
        emit("phase", {"phase": "tls_scan", "hosts": targets.split()})
        run_scan_with_progress(scanner, tqdm, "TLS scan", hosts=targets, ports=job.ports, arguments=TLS_ARGUMENTS)
        collect_scan_results(scanner, job, results, findings, fqdn_cache, cancel_event)
        logger.info("tls_scan_done targets=%s ports=%s", targets, job.ports)

    emit("phase", {"phase": "grading"})
    apply_endpoint_grades(results, findings)
    logger.info("scan_results endpoints=%s rows=%s", len(findings), len(results))
    return results, findings


def execute_scan(job: ScanJob, cancel_event=None, on_event: Hook | None = None, passes: list[tuple[str, str]] | None = None) -> ScanOutcome:
    """Run a validated `ScanJob` and write its exports. Never prints, never exits.

    `passes` (optional) is a list of (targets, ports) executed one after the other with the same job
    settings, used when targets carry their own ports; results are merged into one report.

    Raises ConfigError (invalid input / export path) or PQCPrerequisiteError; other exceptions
    from nmap propagate to the caller, which records them as an execution failure.
    """
    import nmap  # imported lazily: the engine stays importable without nmap for config-only uses

    emit = on_event or (lambda name, data: None)
    validate_scan_input(job)
    pass_list = passes or [(job.targets, job.ports)]
    for pass_targets, pass_ports in pass_list:
        validate_scan_input(ScanJob(targets=pass_targets, ports=pass_ports, crypto=job.crypto, ip=job.ip))
    start = time.monotonic()
    logger = configure_logging(job)
    scan_timestamp = local_scan_timestamp()
    export_paths = build_export_paths(job, local_report_timestamp())
    targets = normalize_targets(job.targets)

    if job.crypto == "pqc":
        emit("phase", {"phase": "pqc_preflight"})
        openssl_version, job.pqc_groups = check_pqc_prerequisites()
        logger.info("pqc_preflight_passed openssl_version=%s groups=%s", openssl_version, ",".join(job.pqc_groups))

    scanned: list[str] = []
    skipped: list[str] = []

    def host_done(host, was_scanned):
        (scanned if was_scanned else skipped).append(host)
        emit("host_done", {"host": host, "scanned": was_scanned})

    logger.info("scan_start targets=%s ports=%s workers=%s crypto=%s", targets, job.ports, job.workers, job.crypto)
    results, findings = [], {}
    for pass_targets, pass_ports in pass_list:
        if cancel_event is not None and cancel_event.is_set():
            skipped.extend(normalize_targets(pass_targets).split())
            continue
        pass_job = ScanJob(**{**job.__dict__, "targets": pass_targets, "ports": pass_ports})
        pass_results, pass_findings = collect_job_results(
            pass_job, normalize_targets(pass_targets), logger, nmap, QuietProgress, cancel_event, on_event, host_done
        )
        results.extend(pass_results)
        findings.update(pass_findings)
    cancelled = bool(cancel_event is not None and cancel_event.is_set())
    duration = round(time.monotonic() - start, 2)

    emit("phase", {"phase": "reporting"})
    written = write_exports(results, job, scan_timestamp, export_paths, duration) if export_paths else []
    model = report_model_to_dict(build_report_model(results, job, scan_timestamp, duration))
    logger.info("scan_end status=%s duration_seconds=%.3f", "cancelled" if cancelled else "success", duration)
    return ScanOutcome(
        status="cancelled" if cancelled else "completed",
        results=results,
        findings=findings,
        written_files=written,
        report_model=model,
        scanned_hosts=scanned,
        skipped_hosts=skipped,
        duration_seconds=duration,
    )
