"""Scan subprocess: runs the engine for one snapshot, with no database access.

Usage: python -m tls_scan_app.workers.child <snapshot.json> <outcome.json>
Emits one JSON event per line on stdout. SIGTERM requests a cooperative cancellation: hosts not yet
started are skipped and the partial results are still written.
"""
from __future__ import annotations

import json
import signal
import sys
import threading
from pathlib import Path

from tls_scan_app.services.planner import job_from_snapshot
from tls_scanner.runner import execute_scan


def emit(name: str, data: dict) -> None:
    print(json.dumps({"event": name, **data}), flush=True)


def main(argv: list[str]) -> int:
    snapshot_path, outcome_path = Path(argv[1]), Path(argv[2])
    payload = json.loads(snapshot_path.read_text())
    cancel = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: cancel.set())
    job, passes = job_from_snapshot(
        payload["snapshot"], payload["run_id"], payload["export_dir"], payload.get("log_file"), payload["max_workers"]
    )
    outcome = execute_scan(job, cancel_event=cancel, on_event=emit, passes=passes)
    outcome_path.write_text(json.dumps({
        "status": outcome.status,
        "report_model": outcome.report_model,
        "written_files": outcome.written_files,
        "scanned_hosts": outcome.scanned_hosts,
        "skipped_hosts": outcome.skipped_hosts,
        "duration_seconds": outcome.duration_seconds,
    }, default=str))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as error:  # noqa: BLE001 - reported to the parent through stderr
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(2)
