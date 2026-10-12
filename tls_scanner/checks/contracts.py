"""
Light contract shared by the complementary TLS checks (identity, stapling, groups, handshake).

A check is a plain function `check(context) -> CheckResult`. `run_check` executes it with the common
guarantees: an unexpected exception becomes an ERROR result, a cancelled scan or an exhausted time
budget gives NOT_TESTED, and the duration is recorded. A check that cannot reach a robust conclusion
returns INCONCLUSIVE instead of guessing.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

PASS = "PASS"
FAIL = "FAIL"
NOT_TESTED = "NOT_TESTED"
NOT_APPLICABLE = "NOT_APPLICABLE"
INCONCLUSIVE = "INCONCLUSIVE"
ERROR = "ERROR"

CHECK_STATUSES = (PASS, FAIL, NOT_TESTED, NOT_APPLICABLE, INCONCLUSIVE, ERROR)

MAX_EVIDENCE_ITEMS = 12
MAX_EVIDENCE_CHARS = 240

DEFAULT_PROBE_TIMEOUT_SECONDS = 10
DEFAULT_TIME_BUDGET_SECONDS = 120


@dataclass(frozen=True)
class CheckContext:
    """What a check may know about the endpoint. Nothing here is mutated by a check."""

    host: str  # address scanned (IP literal as reported by Nmap)
    port: int
    protocol: str = "tcp"
    reference_names: tuple[str, ...] = ()  # names actually requested by the user for this address (never a PTR)
    sni: str = ""  # server name used by the main scan, when any
    observed_versions: tuple[str, ...] = ()  # e.g. ("TLSv1.2", "TLSv1.3"), proven by the main scan
    options: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = DEFAULT_PROBE_TIMEOUT_SECONDS
    deadline: float | None = None  # time.monotonic() value after which no new probe may start
    cancel_event: threading.Event | None = None

    def cancelled(self) -> bool:
        return self.cancel_event is not None and self.cancel_event.is_set()

    def time_left(self) -> float:
        return float("inf") if self.deadline is None else self.deadline - time.monotonic()

    def probe_timeout(self) -> float:
        """Timeout of the next connection: the configured one, never more than the remaining budget."""
        return max(0.5, min(float(self.timeout_seconds), self.time_left()))

    def can_probe(self) -> bool:
        return not self.cancelled() and self.time_left() > 0.5

    @property
    def starttls(self) -> str:
        from ..pki import starttls_protocol_for_port

        return starttls_protocol_for_port(self.port)


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    status: str
    message: str = ""
    observations: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[str, ...] = ()
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CheckFunction = Callable[[CheckContext], CheckResult]


def bounded_evidence(items) -> tuple[str, ...]:
    """Evidence is limited and single-line: a few short facts, never raw captures or secrets."""
    cleaned = []
    for item in items:
        text = " ".join(str(item).split())
        if text:
            cleaned.append(text[:MAX_EVIDENCE_CHARS])
        if len(cleaned) >= MAX_EVIDENCE_ITEMS:
            break
    return tuple(cleaned)


def result(check_id: str, status: str, message: str = "", observations: dict[str, Any] | None = None, evidence=()) -> CheckResult:
    return CheckResult(check_id, status, message, dict(observations or {}), bounded_evidence(evidence))


def run_check(check_id: str, function: CheckFunction, context: CheckContext) -> CheckResult:
    """Execute one check; never raises."""
    if context.cancelled():
        return result(check_id, NOT_TESTED, "scan cancelled before the check started")
    if context.time_left() <= 0.5:
        return result(check_id, NOT_TESTED, "endpoint time budget exhausted before the check started")
    started = time.monotonic()
    try:
        outcome = function(context)
    except Exception as error:  # a failing check must never fail the campaign
        outcome = result(check_id, ERROR, f"{type(error).__name__}: {error}"[:300])
    if outcome.status not in CHECK_STATUSES:
        outcome = result(check_id, ERROR, f"check returned an unknown status {outcome.status!r}")
    return CheckResult(
        outcome.check_id or check_id,
        outcome.status,
        outcome.message,
        outcome.observations,
        outcome.evidence,
        int((time.monotonic() - started) * 1000),
    )
