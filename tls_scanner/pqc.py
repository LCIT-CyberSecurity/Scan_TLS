"""
OpenSSL prerequisites and post-quantum TLS compliance checks.

Called by:
- `tls_scanner.cli`, before a scan in PQC mode;
- `tls_scanner.scanner`, to probe the negotiated TLS group;
- PQC tests.

Produces:
- a validated OpenSSL version;
- available PQC groups;
- OK/KO statuses for the post-quantum compliance criterion.
"""

import re
import shutil
import subprocess

from .constants import MINIMUM_PQC_OPENSSL_VERSION, PQC_TLS_GROUPS
from .models import PQCPrerequisiteError


def parse_openssl_version(version_output):
    match = re.search(r"\bOpenSSL\s+(\d+)\.(\d+)\.(\d+)", version_output)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


# PQC mode depends on a recent OpenSSL build and at least one supported hybrid TLS group.
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


def format_openssl_endpoint(host, port):
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


# Probe groups one by one because OpenSSL reports the negotiated group only after a real handshake.
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
