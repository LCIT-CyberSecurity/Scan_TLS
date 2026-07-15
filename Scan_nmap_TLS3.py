import argparse
import csv
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone


MINIMUM_PQC_OPENSSL_VERSION = (3, 5, 0)
PQC_TLS_GROUPS = (
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
)

STARTUP_BANNER = """
┌──[ TLS_SCAN ]────────────────────────────────────────────┐
│  by LCIT Cybersecurity                                   │
├──────────────────────────────────────────────────────────┤
│  > TLS Reconnaissance                                    │
│  > Crypto Inventory | CBOM | Post-Quantum Readiness      │
└──[ Know your crypto surface. ]───────────────────────────┘
""".strip()


class PQCPrerequisiteError(RuntimeError):
    pass


@dataclass
class ScanJob:
    targets: str
    ports: str
    crypto: str
    ip: bool
    csv_filename: str | None = None
    export_format: str | None = None
    pqc_groups: tuple[str, ...] = ()


def print_startup_banner():
    print(STARTUP_BANNER)


# Command-line parsing and input normalization.
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
        help="export results to .csv or CycloneDX .cbom.json",
    )
    parser.add_argument(
        "targets",
        help="comma-separated FQDNs, IP addresses, or subnets",
    )
    parser.add_argument(
        "csv_filename",
        nargs="?",
        help="optional CSV output filename (legacy syntax)",
    )
    args = parser.parse_args()
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
        elif lower_filename.endswith(".csv") or not explicit_export:
            args.export_format = "csv"
        else:
            parser.error("--export filename must end with .csv or .cbom.json")
    return args


def build_cli_scan_job(args):
    return ScanJob(
        targets=args.targets,
        ports=getattr(args, "ports", "fast"),
        crypto=getattr(args, "crypto", "standard"),
        ip=getattr(args, "ip", False),
        csv_filename=getattr(args, "csv_filename", None),
        export_format=getattr(args, "export_format", None),
    )


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
    job = build_cli_scan_job(cli_args)
    scan_timestamp = (
        datetime.now(timezone.utc).isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    print_startup_banner()
    targets = normalize_targets(job.targets)
    if not targets:
        print("At least one target is required.")
        return 1

    if job.crypto == "pqc":
        try:
            openssl_version, job.pqc_groups = check_pqc_prerequisites()
        except PQCPrerequisiteError as error:
            print(error, file=sys.stderr)
            return 2
        print(f"PQC preflight check passed: {openssl_version}")
        print("Compliance criterion: POST-QUANTUM")

    nmap, PrettyTable, tqdm = load_dependencies()
    print("Initializing TLS information scan...")
    results = []
    findings = {}
    fqdn_cache = resolve_target_fqdns(targets)
    tls_arguments = (
        "-sV --version-light --script ssl-cert,ssl-enum-ciphers"
    )

    # Discovery modes first identify open ports, then run TLS scripts on them.
    if job.ports in ["fast", "all"]:
        scan_label = "common" if job.ports == "fast" else "all"
        print(f"Discovering open TCP ports ({scan_label} ports)...")
        open_ports = discover_open_tcp_ports(
            nmap,
            tqdm,
            targets,
            job.ports,
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
                job,
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

    apply_endpoint_grades(results, findings)

    if not results:
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

    if job.csv_filename:
        if job.export_format == "cbom":
            cbom = build_cbom(results, pqc=job.crypto == "pqc")
            with open(job.csv_filename, "w", encoding="utf-8") as file:
                json.dump(cbom, file, indent=2)
                file.write("\n")
        else:
            csv_headers, csv_rows = build_csv_export(
                results, job, scan_timestamp
            )
            with open(job.csv_filename, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(csv_headers)
                writer.writerows(csv_rows)
        print(f"\nResults have been saved to {job.csv_filename}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
