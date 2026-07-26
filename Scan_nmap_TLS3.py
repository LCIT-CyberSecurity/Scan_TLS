"""Backward-compatible entry point for the TLS scanner CLI."""

# Keep this root-level script so existing commands keep working:
# python3 Scan_nmap_TLS3.py --config config/config.yaml --report NAME
# These standard-library imports preserve old monkeypatch targets on this module.
import shutil
import socket
import subprocess
import sys

from tls_scanner import *  # noqa: F401,F403
from tls_scanner.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
