"""Root entry point of the Orion Standalone command line (the native engine, without the WebUI)."""

# python3 orion.py --config config/config.yaml --report NAME
from tls_scanner import *  # noqa: F401,F403
from tls_scanner.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
