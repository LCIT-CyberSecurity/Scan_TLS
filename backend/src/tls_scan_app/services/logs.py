"""Technical logging with correlation ids and secret scrubbing."""
from __future__ import annotations

import logging
import re

SECRET_RE = re.compile(r"(?i)(password|passwd|secret|token|cookie|authorization|api[_-]?key)(\s*[=:]\s*)([^\s,;&\"']+)")
URL_CRED_RE = re.compile(r"(\w+://)([^/\s:@]+):([^/\s@]+)@")


def scrub_text(text: str) -> str:
    return URL_CRED_RE.sub(r"\1\2:***@", SECRET_RE.sub(r"\1\2***", text))


class ScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = scrub_text(str(record.getMessage()))
        record.args = ()
        return True


def configure_logging(settings, component: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(f"%(asctime)s %(levelname)s {component} %(name)s %(message)s"))
    handler.addFilter(ScrubFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.log_level.upper())
