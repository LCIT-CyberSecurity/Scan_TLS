"""
Certificate inventory extracted from Nmap ssl-cert output.
"""

import re
from datetime import datetime

from ..crypto_policy import extract_public_key, extract_signature_algorithm
from ..models import CertificateInfo


def extract_line_value(certificate_output, label):
    match = re.search(
        rf"^\s*{re.escape(label)}:\s*(.+?)\s*$",
        certificate_output,
        re.IGNORECASE | re.MULTILINE,
    )
    return match.group(1).strip() if match else "-"


def extract_not_after(certificate_output):
    match = re.search(
        r"^\s*Not valid after:\s*([^\sT]+)",
        certificate_output,
        re.IGNORECASE | re.MULTILINE,
    )
    return match.group(1).strip() if match else "N/A"


def extract_subject_alternative_names(certificate_output):
    value = extract_line_value(certificate_output, "Subject Alternative Name")
    if value == "-":
        return ()
    names = []
    for item in value.split(","):
        cleaned = item.strip()
        if ":" in cleaned:
            cleaned = cleaned.split(":", 1)[1].strip()
        if cleaned:
            names.append(cleaned)
    return tuple(names)


def normalize_identity(value):
    return re.sub(r"\s+", "", value).casefold()


def days_until(not_after):
    try:
        expiry = datetime.strptime(not_after, "%Y-%m-%d")
    except ValueError:
        return None
    return (expiry.date() - datetime.now().date()).days


def detect_self_signed(subject, issuer):
    if subject == "-" or issuer == "-":
        return "unknown"
    return "yes" if normalize_identity(subject) == normalize_identity(issuer) else "no"


def signature_hash_summary(signature_algorithm):
    normalized = signature_algorithm.upper().replace("-", "").replace("_", "")
    if "SHA512" in normalized:
        return "SHA-512"
    if "SHA384" in normalized:
        return "SHA-384"
    if "SHA256" in normalized:
        return "SHA-256"
    if "SHA1" in normalized or normalized.endswith("SHA"):
        return "SHA-1"
    if "MD5" in normalized:
        return "MD5"
    return signature_algorithm or "unknown"


def certificate_crypto_summary(certificate_info):
    key = certificate_info.public_key_type
    if certificate_info.public_key_bits is not None:
        key = f"{key} {certificate_info.public_key_bits}"
    return f"{key} / {signature_hash_summary(certificate_info.signature_algorithm)}"


def build_certificate_info(certificate_output):
    public_key_type, public_key_bits = extract_public_key(certificate_output)
    subject = extract_line_value(certificate_output, "Subject")
    issuer = extract_line_value(certificate_output, "Issuer")
    not_after = extract_not_after(certificate_output)
    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        subject_alternative_names=extract_subject_alternative_names(certificate_output),
        not_after=not_after,
        days_remaining=days_until(not_after),
        public_key_type=public_key_type,
        public_key_bits=public_key_bits,
        signature_algorithm=extract_signature_algorithm(certificate_output),
        self_signed=detect_self_signed(subject, issuer),
    )
