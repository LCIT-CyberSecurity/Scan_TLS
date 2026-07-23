"""
Shared constants for the TLS scanner.

Called by:
- configuration, CLI, logging, PQC, and export modules;
- the public facade in `tls_scanner.__init__`.

Produces:
- default values, supported export formats, log levels, and common PQC settings.
"""

import logging
import re

DEFAULT_CONFIG_FILE = "config/config.yaml"
DEFAULT_LOG_FILE = "logs/scan.log"
DEFAULT_EXPORT_DIR = "scan_reports"
DEFAULT_TARGETS_DIR = "config/targets_scan"
DEFAULT_POLICIES_DIR = "config/encryption_policy"
ALLOWED_EXPORT_FORMATS = {"csv", "cbom", "md"}
SAFE_CONFIG_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
MINIMUM_PQC_OPENSSL_VERSION = (3, 5, 0)
PQC_TLS_GROUPS = (
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
)
DEFAULT_WORKERS = 4
MAX_WORKERS = 32

LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}
