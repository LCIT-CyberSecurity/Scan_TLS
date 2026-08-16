"""Root entry point for the TLS scanner CLI."""

# Keep a root-level script for direct execution:
# python3 tls_scan.py --config config/config.yaml --report NAME
from tls_scanner import *  # noqa: F401,F403
from tls_scanner.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
