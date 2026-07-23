"""
Standard TLS cryptographic analysis and compliance grading.

Called by:
- `tls_scanner.scanner`, to evaluate each observed cipher suite;
- `tls_scanner.cli`, to apply endpoint grades after collection;
- TLS compliance and grading tests.

Produces:
- OK/KO compliance statuses with reasons;
- endpoint grades;
- certificate and cipher details extracted from Nmap script output.
"""

import re
from datetime import datetime

from .models import EncryptionPolicy

DEFAULT_TLS_POLICY = EncryptionPolicy(
    name="anssi_encryption_policy",
    version="1.0",
    description="ANSSI TLS encryption policy template.",
    allowed_versions=("TLSv1.2", "TLSv1.3"),
    allowed_cipher_algorithms=("AES-GCM", "AES-CCM", "CHACHA20-POLY1305"),
    allowed_signature_hashes=("SHA-256", "SHA-384", "SHA-512"),
    minimum_rsa_bits=2048,
)


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


def normalize_algorithm_name(value):
    return value.upper().replace("-", "_")


def normalize_signature_name(value):
    return value.upper().replace("-", "").replace("_", "")


def selected_policies(policies=None):
    return tuple(policies or (DEFAULT_TLS_POLICY,))


def cipher_matches_algorithm(cipher_suite, algorithm):
    normalized_cipher = normalize_algorithm_name(cipher_suite)
    normalized_algorithm = normalize_algorithm_name(algorithm)
    if normalized_algorithm == "AES_GCM":
        return "AES" in normalized_cipher and "GCM" in normalized_cipher
    if normalized_algorithm == "AES_CCM":
        return "AES" in normalized_cipher and "CCM" in normalized_cipher
    if normalized_algorithm == "CHACHA20_POLY1305":
        return "CHACHA20_POLY1305" in normalized_cipher
    return normalized_algorithm in normalized_cipher


def signature_matches_hash(signature_algorithm, allowed_hash):
    normalized_signature = normalize_signature_name(signature_algorithm)
    normalized_hash = normalize_signature_name(allowed_hash)
    return normalized_hash in normalized_signature

def cipher_suite_hashes(cipher_suite):
    hashes = []
    for token in normalize_algorithm_name(cipher_suite).split("_"):
        if token in {"MD5", "SHA", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}:
            hashes.append("SHA1" if token == "SHA" else token)
    return tuple(hashes)


def cipher_suite_hash_allowed(cipher_suite, policy):
    hashes = cipher_suite_hashes(cipher_suite)
    if not hashes:
        return True
    return all(
        any(normalize_signature_name(cipher_hash) == normalize_signature_name(allowed_hash)
            for allowed_hash in policy.allowed_signature_hashes)
        for cipher_hash in hashes
    )


def policy_allows_cipher_suite(tls_version, cipher_suite, policy):
    if tls_version not in policy.allowed_versions:
        return False, "TLS version"
    if not cipher_suite_hash_allowed(cipher_suite, policy):
        if any(cipher_hash in {"SHA1", "MD5"} for cipher_hash in cipher_suite_hashes(cipher_suite)):
            return False, "SHA-1"
        return False, "Signature hash"
    if not any(
        cipher_matches_algorithm(cipher_suite, algorithm)
        for algorithm in policy.allowed_cipher_algorithms
    ):
        return False, "Cipher suite"
    return True, ""


def policy_allows_signature(signature_algorithm, policy):
    if not signature_algorithm:
        return True
    return any(
        signature_matches_hash(signature_algorithm, allowed_hash)
        for allowed_hash in policy.allowed_signature_hashes
    )


def is_cipher_suite_compliant(tls_version, cipher_suite, policies=None):
    return all(
        policy_allows_cipher_suite(tls_version, cipher_suite, policy)[0]
        for policy in selected_policies(policies)
    )


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
    policies=None,
):
    compliance, _ = evaluate_compliance(
        tls_version,
        cipher_suite,
        cert_validity,
        certificate_output,
        public_key_type,
        public_key_bits,
        policies,
    )
    return compliance


# Return the first failing compliance reason; this keeps remediation messages actionable.
def evaluate_compliance(
    tls_version,
    cipher_suite,
    cert_validity,
    certificate_output,
    public_key_type,
    public_key_bits,
    policies=None,
):
    signature_algorithm = extract_signature_algorithm(certificate_output)
    policies = selected_policies(policies)

    for policy in policies:
        cipher_allowed, reason = policy_allows_cipher_suite(
            tls_version,
            cipher_suite,
            policy,
        )
        if not cipher_allowed:
            return "KO", reason
        if not policy_allows_signature(signature_algorithm, policy):
            return "KO", "Signature hash"
        if public_key_type == "RSA" and (
            public_key_bits is None or public_key_bits < policy.minimum_rsa_bits
        ):
            return "KO", "RSA key size"

    try:
        cert_expiry_date = datetime.strptime(cert_validity, "%Y-%m-%d")
    except ValueError:
        return "KO", "Certificate date"

    if cert_expiry_date < datetime.now():
        return "KO", "Certificate expired"

    return "OK", ""


# Endpoint grading is intentionally stricter than per-row compliance and uses the weakest observed signal.
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
