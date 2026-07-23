"""
Application logging configuration.

Called by:
- `tls_scanner.cli`, when a scan or dry-run starts;
- logging tests.

Produces:
- a configured `tls_scan` logger with level, format, run ID, and optional file output.
"""

import logging
import time
from pathlib import Path

from .constants import LOG_LEVELS


def configure_logging(job):
    logger = logging.getLogger("tls_scan")
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()
    logger.setLevel(LOG_LEVELS[job.log_level])
    logger.propagate = False

    if job.log_file is None:
        logger.addHandler(logging.NullHandler())
        return logging.LoggerAdapter(logger, {"scan_run_id": job.scan_run_id})

    log_path = Path(job.log_file)
    if log_path.parent != Path("."):
        log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(LOG_LEVELS[job.log_level])
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s run_id=%(scan_run_id)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logging.LoggerAdapter(logger, {"scan_run_id": job.scan_run_id})
