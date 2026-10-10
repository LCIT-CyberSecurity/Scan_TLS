"""Worker restart recovery and execution timeout."""
from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, text

from conftest import make_definition, wait_final, wait_for


def test_stale_running_run_is_failed_explicitly_after_worker_loss(user, catalog):
    definition = make_definition(user, catalog, ["192.0.2.77"], name="orphan")
    run_id = uuid.uuid4()
    engine = create_engine(os.environ["TLS_SCAN_DATABASE_URL"])
    with engine.begin() as db:
        db.execute(text(
            "INSERT INTO scan_runs (id, definition_id, name, status, phase, fingerprint, config_snapshot, policy_versions, queued_at, started_at, heartbeat_at, "
            "cancel_requested, error, report_dir) VALUES (:id, :d, 'orphan', 'running', 'tls_scan', :fp, '{}', '[]', now(), now(), :hb, false, '', '')"
        ), {"id": run_id, "d": definition["id"], "fp": uuid.uuid4().hex * 2, "hb": datetime.now(UTC) - timedelta(minutes=10)})
    final = wait_for(lambda: (r := user.get(f"/api/scan-runs/{run_id}").json())["status"] != "running" and r, 30)
    assert final["status"] == "failed" and "worker lost" in final["error"]


@pytest.mark.skipif(int(os.environ.get("TLS_SCAN_MAX_SCAN_DURATION_SECONDS", "300")) > 30, reason="needs a stack started with TEST_MAX_DURATION<=30")
def test_run_exceeding_max_duration_expires(user, catalog):
    definition = make_definition(user, catalog, ["10.254.0.0/20"], name="too-long")
    run = user.post(f"/api/scan-definitions/{definition['id']}/run").json()
    final = wait_final(user, run["run_id"], 120)
    assert final["status"] == "expired"
