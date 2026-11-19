"""Former root entry point of the Standalone command line, kept after the Orion rebranding.

Same arguments and behaviour as `orion.py`, which replaces it: existing scripts, cron jobs and documentation that run
`python3 tls_scan.py ...` keep working. Deprecated; it will be removed in a later major version.
"""

# python3 tls_scan.py --config config/config.yaml --report NAME
from tls_scanner import *  # noqa: F401,F403
from tls_scanner.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
