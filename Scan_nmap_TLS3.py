import argparse
import csv
import re
import socket
import sys
import threading
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan TLS configurations on one or more targets."
    )
    parser.add_argument(
        "-i",
        "--ip",
        action="store_true",
        help="disable DNS resolution and leave the FQDN column empty",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="443",
        type=parse_ports,
        help=(
            'TCP ports to test, for example "443,8443,9000-9010", '
            '"fast", or "all"'
        ),
    )
    parser.add_argument(
        "targets",
        help="comma-separated FQDNs, IP addresses, or subnets",
    )
    parser.add_argument(
        "csv_filename",
        nargs="?",
        help="optional CSV output filename",
    )
    return parser.parse_args()


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


def resolve_fqdn(ip_address):
    try:
        fqdn = socket.gethostbyaddr(ip_address)[0].rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return ""
    return fqdn if fqdn != ip_address else ""


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
        public_key_bits is None or public_key_bits < 3072
    ):
        return "KO", "RSA key size"

    try:
        cert_expiry_date = datetime.strptime(cert_validity, "%Y-%m-%d")
    except ValueError:
        return "KO", "Certificate date"

    if cert_expiry_date < datetime.now():
        return "KO", "Certificate expired"

    return "OK", ""


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
        row.insert(3, endpoint_grades[(row[0], row[2])])


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

    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()

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
            for tls_version, cipher_suite in extract_cipher_suites(cipher_output):
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
                results.append(
                    [
                        host,
                        fqdn,
                        port,
                        tls_version,
                        cipher_suite,
                        public_key,
                        cert_validity,
                        compliance,
                        reason,
                    ]
                )


def main():
    args = parse_args()
    targets = normalize_targets(args.targets)
    if not targets:
        print("At least one target is required.")
        return 1

    nmap, PrettyTable, tqdm = load_dependencies()
    print("Initializing TLS information scan...")
    results = []
    findings = {}
    fqdn_cache = {}
    tls_arguments = (
        "-sV --version-light --script ssl-cert,ssl-enum-ciphers"
    )

    if args.ports in ["fast", "all"]:
        scan_label = "common" if args.ports == "fast" else "all"
        print(f"Discovering open TCP ports ({scan_label} ports)...")
        open_ports = discover_open_tcp_ports(
            nmap,
            tqdm,
            targets,
            args.ports,
        )
        progress = tqdm(total=len(open_ports), desc="Scanning hosts")
        for host, ports in open_ports.items():
            scanner = nmap.PortScanner()
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
                args,
                results,
                findings,
                fqdn_cache,
            )
            progress.update(1)
        progress.close()
    else:
        scanner = nmap.PortScanner()
        run_scan_with_progress(
            scanner,
            tqdm,
            "TLS scan",
            hosts=targets,
            ports=args.ports,
            arguments=tls_arguments,
        )
        collect_scan_results(
            scanner,
            args,
            results,
            findings,
            fqdn_cache,
        )

    apply_endpoint_grades(results, findings)

    table = PrettyTable(
        [
            "IP",
            "FQDN",
            "Port",
            "Grade",
            "TLS Version",
            "Cipher Suite",
            "Public Key",
            "Certificate Validity",
            "Compliance",
        ]
    )
    for row in results:
        table.add_row(row[:-1])
    print("\n" + str(table))

    if args.csv_filename:
        with open(args.csv_filename, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(
                [
                    "IP",
                    "FQDN",
                    "Port",
                    "Grade",
                    "TLS Version",
                    "Cipher Suite",
                    "Public Key",
                    "Certificate Validity",
                    "Compliance",
                    "Reason",
                ]
            )
            writer.writerows(results)
        print(f"\nResults have been saved to {args.csv_filename}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
