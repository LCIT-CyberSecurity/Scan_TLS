"""Nmap execution and transformation of raw script output into result rows."""

import sys
import threading
import time

from .crypto_policy import evaluate_compliance, extract_cipher_suites, extract_public_key
from .network import resolve_fqdn
from .pqc import evaluate_pqc_compliance, probe_pqc_key_exchange


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
