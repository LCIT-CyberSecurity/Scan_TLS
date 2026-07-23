"""TLS certificate, cipher, compliance, and endpoint grading logic."""

import re
from datetime import datetime


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
