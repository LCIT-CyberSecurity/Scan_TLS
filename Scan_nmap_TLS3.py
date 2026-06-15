import argparse
import csv
import re
import socket
import sys
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
        "targets",
        help="comma-separated FQDNs, IP addresses, or subnets",
    )
    parser.add_argument(
        "csv_filename",
        nargs="?",
        help="optional CSV output filename",
    )
    return parser.parse_args()


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

    authenticated_encryption = any(
        algorithm in cipher_suite
        for algorithm in ["_GCM_", "_CCM_", "CHACHA20_POLY1305"]
    ) or cipher_suite.endswith(("_GCM", "_CCM"))
    if not authenticated_encryption:
        return False

    if tls_version == "TLSv1.3":
        return True

    return cipher_suite.startswith(("TLS_ECDHE_", "TLS_DHE_"))


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
    signature_algorithm = extract_signature_algorithm(certificate_output)
    security_details = f"{cipher_suite} {signature_algorithm}".upper()
    normalized_details = security_details.replace("-", "").replace("_", "")

    if "MD5" in normalized_details or "SHA1" in normalized_details:
        return "KO"

    if tls_version not in ["TLSv1.2", "TLSv1.3"]:
        return "KO"

    if not is_cipher_suite_compliant(tls_version, cipher_suite):
        return "KO"

    if public_key_type == "RSA" and (
        public_key_bits is None or public_key_bits < 3072
    ):
        return "KO"

    try:
        cert_expiry_date = datetime.strptime(cert_validity, "%Y-%m-%d")
    except ValueError:
        return "KO"

    return "KO" if cert_expiry_date < datetime.now() else "OK"


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


def main():
    args = parse_args()
    targets = normalize_targets(args.targets)
    if not targets:
        print("At least one target is required.")
        return 1

    nmap, PrettyTable, tqdm = load_dependencies()
    scanner = nmap.PortScanner()

    print("Initializing TLS information scan...")
    scanner.scan(
        hosts=targets,
        arguments="-p 443 --script ssl-cert,ssl-enum-ciphers",
    )

    results = []
    hosts = list(scanner.all_hosts())
    progress = tqdm(total=len(hosts), desc="Scanning hosts")

    for host in hosts:
        progress.update(1)
        if "tcp" not in scanner[host] or 443 not in scanner[host]["tcp"]:
            continue

        port_info = scanner[host]["tcp"][443]
        if "script" not in port_info:
            continue

        certificate_output = port_info["script"].get("ssl-cert", "")
        public_key_type, public_key_bits = extract_public_key(certificate_output)
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
        fqdn = "" if args.ip else resolve_fqdn(host)
        for tls_version, cipher_suite in extract_cipher_suites(cipher_output):
            compliance = check_compliance(
                tls_version,
                cipher_suite,
                cert_validity,
                certificate_output,
                public_key_type,
                public_key_bits,
            )
            results.append(
                [
                    host,
                    fqdn,
                    443,
                    tls_version,
                    cipher_suite,
                    public_key,
                    cert_validity,
                    compliance,
                ]
            )

    progress.close()

    table = PrettyTable(
        [
            "IP",
            "FQDN",
            "Port",
            "TLS Version",
            "Cipher Suite",
            "Public Key",
            "Certificate Validity",
            "Compliance",
        ]
    )
    for row in results:
        table.add_row(row)
    print("\n" + str(table))

    if args.csv_filename:
        with open(args.csv_filename, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(
                [
                    "IP",
                    "FQDN",
                    "Port",
                    "TLS Version",
                    "Cipher Suite",
                    "Public Key",
                    "Certificate Validity",
                    "Compliance",
                ]
            )
            writer.writerows(results)
        print(f"\nResults have been saved to {args.csv_filename}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
