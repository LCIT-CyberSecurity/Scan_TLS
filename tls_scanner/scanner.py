"""
Nmap execution and transformation of TLS script output into structured results.

Called by:
- `tls_scanner.cli`, to run port discovery and TLS scans;
- scan and progress tests.

Produces:
- result rows ready for terminal display and exports;
- per-endpoint findings later used for grading.
"""

import sys
import threading
from concurrent.futures import ThreadPoolExecutor
import time

from .checks import build_certificate_info, certificate_crypto_summary
from .crypto_policy import evaluate_compliance, extract_cipher_suites
from .network import resolve_fqdn
from .pki import REVOCATION_REVOKED, TRUST_UNTRUSTED, collect_peer_certificate_chain, revocation_result_not_tested, trust_result_not_tested, validate_certificate_revocation, validate_peer_chain
from .pqc import evaluate_pqc_compliance, probe_pqc_key_exchange


def trust_display_values(trust_result):
    if trust_result.trust_classification == TRUST_UNTRUSTED:
        return "N/A", "N/A"
    return ", ".join(trust_result.trusted_by) or "N/A", trust_result.trust_anchor or "N/A"


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


# Discovery modes reduce TLS scan time by probing only ports Nmap reports as open.
def discover_open_tcp_ports(nmap, tqdm, targets, mode):
    scanner = nmap.PortScanner()
    scan_options = {
        "fast": {
            "arguments": "--top-ports 2000 -T4 --open --max-retries 2",
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


# Convert each TLS cipher finding into a row while keeping endpoint findings for grading.
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
            certificate_info = build_certificate_info(certificate_output)
            endpoint_id = f"{host}:{port}/tcp"
            if args.certificate_trust_enabled or args.certificate_revocation_enabled:
                chain = collect_peer_certificate_chain(host, port, fqdn)
            else:
                chain = None
            if args.certificate_trust_enabled and chain is not None:
                trust_result = validate_peer_chain(
                    chain,
                    args.certificate_trust_stores,
                    enabled=args.certificate_trust_enabled,
                )
            else:
                trust_result = trust_result_not_tested("trust validation disabled")
            if args.certificate_revocation_enabled and chain is not None:
                revocation_result = validate_certificate_revocation(
                    chain,
                    enabled=args.certificate_revocation_enabled,
                    ocsp_enabled=args.certificate_revocation_ocsp_enabled,
                    crl_enabled=args.certificate_revocation_crl_enabled,
                    timeout_seconds=args.certificate_revocation_timeout_seconds,
                    max_response_bytes=args.certificate_revocation_max_response_bytes,
                    allow_private_urls=args.certificate_revocation_allow_private_urls,
                )
            else:
                revocation_result = revocation_result_not_tested("revocation validation disabled")
            args.certificate_trust_results[endpoint_id] = trust_result
            args.certificate_revocation_results[endpoint_id] = revocation_result
            public_key_type = certificate_info.public_key_type
            public_key_bits = certificate_info.public_key_bits
            public_key = public_key_type
            if public_key_bits is not None:
                public_key = f"{public_key_type} {public_key_bits} bits"
            cert_validity = certificate_info.not_after
            certificate_san = ", ".join(certificate_info.subject_alternative_names) or "-"

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
                        args.policies,
                    )
                if trust_result.trust_classification == TRUST_UNTRUSTED:
                    compliance, reason = "KO", "Certificate chain untrusted"
                if revocation_result.revocation_status == REVOCATION_REVOKED:
                    compliance, reason = "KO", "Certificate revoked"
                finding = {
                    "tls_version": tls_version,
                    "cipher_suite": cipher_suite,
                    "cert_validity": cert_validity,
                    "certificate_output": certificate_output,
                    "public_key_type": public_key_type,
                    "public_key_bits": public_key_bits,
                    "trust_classification": trust_result.trust_classification,
                    "revocation_status": revocation_result.revocation_status,
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
                row.extend(
                    [
                        certificate_crypto_summary(certificate_info),
                        certificate_info.self_signed,
                        certificate_info.days_remaining
                        if certificate_info.days_remaining is not None
                        else "unknown",
                        certificate_info.issuer,
                        certificate_info.subject,
                        certificate_san,
                        certificate_info.public_key_type,
                        certificate_info.public_key_bits
                        if certificate_info.public_key_bits is not None
                        else "unknown",
                        certificate_info.signature_algorithm or "unknown",
                        trust_result.trust_classification,
                        *trust_display_values(trust_result),
                        trust_result.chain_validation_status,
                        revocation_result.revocation_status,
                        revocation_result.ocsp_status,
                        revocation_result.crl_status,
                        compliance,
                        reason,
                    ]
                )
                results.append(row)


# Each worker owns its PortScanner instance; python-nmap scanner objects are not shared across threads.
def scan_tls_host(nmap, tqdm, host, ports, job, fqdn_cache, tls_arguments):
    scanner = nmap.PortScanner()
    host_results = []
    host_findings = {}
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
        host_results,
        host_findings,
        fqdn_cache,
    )
    return host_results, host_findings


def scan_tls_hosts_parallel(nmap, tqdm, open_ports, job, fqdn_cache, tls_arguments, logger):
    if not open_ports:
        return [], {}

    items = sorted(open_ports.items())
    if job.workers == 1:
        results = []
        findings = {}
        for host, ports in items:
            logger.info(
                "tls_scan_start host=%s ports=%s",
                host,
                ",".join(str(port) for port in ports),
            )
            host_results, host_findings = scan_tls_host(
                nmap,
                tqdm,
                host,
                ports,
                job,
                fqdn_cache,
                tls_arguments,
            )
            results.extend(host_results)
            findings.update(host_findings)
            logger.info("tls_scan_done host=%s", host)
        return results, findings

    results_by_host = {}
    findings_by_host = {}
    max_workers = min(job.workers, len(items))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for host, ports in items:
            logger.info(
                "tls_scan_start host=%s ports=%s",
                host,
                ",".join(str(port) for port in ports),
            )
            futures[executor.submit(
                scan_tls_host,
                nmap,
                tqdm,
                host,
                ports,
                job,
                fqdn_cache,
                tls_arguments,
            )] = host

        for future, host in futures.items():
            host_results, host_findings = future.result()
            results_by_host[host] = host_results
            findings_by_host[host] = host_findings
            logger.info("tls_scan_done host=%s", host)

    results = []
    findings = {}
    for host, _ports in items:
        results.extend(results_by_host.get(host, []))
        findings.update(findings_by_host.get(host, {}))
    return results, findings
