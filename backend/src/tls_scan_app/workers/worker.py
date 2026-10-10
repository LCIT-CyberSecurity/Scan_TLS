"""Dedicated scan worker: claims queued runs and supervises one engine subprocess per run."""
from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from tls_scan_app.config import Settings, get_settings
from tls_scan_app.database import make_engine, make_session_factory
from tls_scan_app.models import ScanRun
from tls_scan_app.services import mail, retention, runs
from tls_scan_app.services.logs import configure_logging, scrub_text
from tls_scan_app.services.notifications import notify_run_finished

logger = logging.getLogger("tls_scan_app.worker")
CANCEL_GRACE_SECONDS = 20
HEARTBEAT_SECONDS = 10


def run_subprocess(settings: Settings, session_factory, run_id) -> None:
    """Supervise one scan: heartbeat, progress events, cancellation, timeout, partial results."""
    storage = Path(settings.storage_root)
    export_dir = storage / "reports"
    log_file = storage / "logs" / "scans" / f"{run_id}.log"
    with session_factory() as db:
        run = db.get(ScanRun, run_id)
        snapshot = run.config_snapshot
    with tempfile.TemporaryDirectory(prefix="scan-") as tmp:
        snapshot_path, outcome_path = Path(tmp) / "snapshot.json", Path(tmp) / "outcome.json"
        snapshot_path.write_text(json.dumps({
            "snapshot": snapshot, "run_id": str(run_id), "export_dir": str(export_dir),
            "log_file": str(log_file), "max_workers": settings.max_scan_workers,
        }))
        # The child gets a minimal environment: no database URL, no session secret, no OIDC secret.
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH", "SSL_CERT_FILE")}
        child = subprocess.Popen(
            [sys.executable, "-m", "tls_scan_app.workers.child", str(snapshot_path), str(outcome_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, start_new_session=True,
        )
        import threading

        events, stderr_lines = [], []
        progress = {"hosts_total": None, "hosts_done": 0}
        state = {"phase": "starting"}

        def read_stdout():
            for line in child.stdout:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event") == "phase":
                    state["phase"] = event["phase"]
                    if event.get("hosts") and event["phase"] == "tls_scan":
                        progress["hosts_total"] = len(event["hosts"])
                elif event.get("event") == "host_done":
                    progress["hosts_done"] += 1

        threads = [threading.Thread(target=read_stdout, daemon=True),
                   threading.Thread(target=lambda: stderr_lines.extend(child.stderr), daemon=True)]
        for t in threads:
            t.start()

        start = time.monotonic()
        cancelled = timed_out = False
        term_sent_at = None
        while child.poll() is None:
            time.sleep(1)
            with session_factory() as db:
                run = db.get(ScanRun, run_id)
                run.heartbeat_at, run.phase = datetime.now(UTC), state["phase"]
                run.progress = dict(progress) if progress["hosts_total"] else None
                want_cancel = run.cancel_requested
                db.commit()
            over_time = time.monotonic() - start > settings.max_scan_duration_seconds
            if (want_cancel or over_time) and term_sent_at is None:
                cancelled, timed_out = want_cancel, over_time and not want_cancel
                os.killpg(child.pid, signal.SIGTERM)
                term_sent_at = time.monotonic()
            if term_sent_at and time.monotonic() - term_sent_at > CANCEL_GRACE_SECONDS:
                os.killpg(child.pid, signal.SIGKILL)  # also stops the nmap processes of the group
                break
        child.wait()
        for t in threads:
            t.join(timeout=5)
        # Make sure no nmap is left behind in the child's process group.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

        with session_factory() as db:
            run = db.get(ScanRun, run_id)
            if outcome_path.exists():
                outcome = json.loads(outcome_path.read_text())
                status = runs.final_status(outcome, cancelled, timed_out)
                runs.persist_results(db, run, outcome, status, storage)
            else:
                run.status = "expired" if timed_out else ("cancelled" if cancelled else "failed")
                run.finished_at = datetime.now(UTC)
                run.error = scrub_text("".join(stderr_lines)[-2000:]) or f"engine exited with code {child.returncode}"
                run.duration_seconds = round(time.monotonic() - start, 2)
                from tls_scan_app.services import audit

                audit.record(db, f"scan.{run.status}", actor_label="worker", resource_type="scan_run", resource_id=run.id,
                             outcome="failure", detail={"error": run.error[:300]})
            db.commit()
            notify_run_finished(db, run)
            db.commit()


def main() -> None:
    settings = get_settings()
    configure_logging(settings, "worker")
    engine = make_engine(settings.database_url)
    session_factory = make_session_factory(engine)
    worker_id = f"{socket.gethostname()}-{os.getpid()}"
    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
    logger.info("worker started id=%s max_concurrent=%s", worker_id, settings.max_concurrent_scans)
    import threading

    active: dict = {}
    last_purge = 0.0
    while not stop["flag"]:
        with session_factory() as db:
            runs.recover_stale(db)
            mail.deliver_pending(db, settings)
            if time.monotonic() - last_purge > 3600:
                last_purge = time.monotonic()
                retention.purge(db, Path(settings.storage_root))
            for run_id in [r for r, t in active.items() if not t.is_alive()]:
                active.pop(run_id)
            run = None
            if len(active) < settings.max_concurrent_scans:
                run = runs.claim_next(db, worker_id, settings.max_concurrent_scans)
        if run is not None:
            logger.info("scan_run_id=%s claimed", run.id)
            thread = threading.Thread(target=_guarded, args=(settings, session_factory, run.id), daemon=True)
            active[run.id] = thread
            thread.start()
        else:
            time.sleep(settings.worker_poll_seconds)
    logger.info("worker stopping; waiting for %s active scan(s)", len(active))
    for thread in active.values():
        thread.join(timeout=settings.max_scan_duration_seconds)


def _guarded(settings, session_factory, run_id) -> None:
    try:
        run_subprocess(settings, session_factory, run_id)
    except Exception:  # noqa: BLE001
        logger.exception("scan_run_id=%s supervision failed", run_id)
        with session_factory() as db:
            run = db.get(ScanRun, run_id)
            if run and run.status == "running":
                run.status, run.finished_at, run.error = "failed", datetime.now(UTC), "worker supervision error"
                db.commit()


if __name__ == "__main__":
    main()
