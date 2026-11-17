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
from tls_scan_app.services.ipsec import evaluate_policy, probe
import csv
import html
import io
from datetime import UTC, datetime


def emit(name: str, data: dict) -> None:
    print(json.dumps({"event": name, **data}), flush=True)


def scan_ipsec(config: dict, targets: list[str], export_dir: Path, run_id: str, formats: list[str], cancel, emit):
    """Run bounded IKE probes and keep the observations separate from TLS grades."""
    ike = config["ike"]
    policies = config.get("policies", [])
    observations = []
    total = len(targets) * len(ike["versions"]) * len(ike["ports"])
    done = 0
    for target in targets:
        for version in ike["versions"]:
            for port in ike["ports"]:
                if cancel.is_set():
                    break
                emit("phase", {"phase": "ipsec_probe", "hosts": targets})
                observation = probe(target, version, port, ike.get("timeout_ms", 1000), ike.get("retries", 0),
                                    ike.get("nat_t", True), ike.get("ikev1_transforms", []))
                verdicts = {p["name"]: evaluate_policy(observation, p["content"]) for p in policies}
                values = set(verdicts.values())
                observation["verdict"] = ("non_compliant" if "non_compliant" in values else
                                           "compliant" if values == {"compliant"} else "indeterminate")
                observation["evidence"]["policy_verdicts"] = verdicts
                observation["target"] = target
                observations.append(observation)
                done += 1
                emit("host_done", {"target": target, "hosts_done": done, "hosts_total": total})
            if cancel.is_set():
                break
        if cancel.is_set():
            break

    root = export_dir / run_id
    root.mkdir(parents=True, exist_ok=True)
    rows = [{"target": x["target"], "port": x["port"], "status": x["status"], "ike_version": x["ike_version"],
             "exchange": x["exchange"], "verdict": x["verdict"],
             "policy_verdicts": json.dumps(x.get("evidence", {}).get("policy_verdicts", {}), sort_keys=True),
             **(x["proposal"] or {})} for x in observations]
    fields = ("target", "port", "status", "ike_version", "exchange", "verdict", "policy_verdicts", "encryption", "key_length_bits", "integrity", "prf", "dh_group")
    written = []
    for fmt in formats:
        path = root / f"ipsec-results.{fmt}"
        if fmt == "csv":
            stream = io.StringIO(newline="")
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
            writer.writeheader(); writer.writerows(rows)
            path.write_text(stream.getvalue(), encoding="utf-8")
        elif fmt == "md":
            lines = ["# IPsec / IKE scan results", "", "> Unauthenticated discovery only; tunnel operation was not evaluated.", "",
                     "| " + " | ".join(fields) + " |", "|" + "|".join(["---"] * len(fields)) + "|"]
            lines.extend("| " + " | ".join(str(row.get(key, "")) for key in fields) + " |" for row in rows)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        elif fmt == "html":
            cells = "".join("<tr>" + "".join(f"<td>{html.escape(str(row.get(key, '')))}</td>" for key in fields) + "</tr>" for row in rows)
            path.write_text("<!doctype html><meta charset='utf-8'><title>IPsec scan</title><h1>IPsec / IKE results</h1><p>Unauthenticated discovery only; tunnel operation was not evaluated.</p><table><thead><tr>" + "".join(f"<th>{html.escape(key)}</th>" for key in fields) + f"</tr></thead><tbody>{cells}</tbody></table>", encoding="utf-8")
        else:
            continue
        written.append(str(path))
    return observations, written


def main(argv: list[str]) -> int:
    snapshot_path, outcome_path = Path(argv[1]), Path(argv[2])
    payload = json.loads(snapshot_path.read_text())
    cancel = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: cancel.set())
    if payload["snapshot"].get("control_type") == "ipsec":
        snapshot = payload["snapshot"]
        ike = snapshot["ike"]
        observations = []
        targets = sorted({target for p in snapshot["passes"] for target in p["targets"]})
        total = len(targets) * len(ike["versions"]) * len(ike["ports"])
        done = 0
        for target in targets:
            for version in ike["versions"]:
                for port in ike["ports"]:
                    if cancel.is_set():
                        break
                    emit("phase", {"phase": "ipsec_probe", "hosts": targets})
                    observation = probe(target, version, port, ike.get("timeout_ms", 1000), ike.get("retries", 0),
                                        ike.get("nat_t", True), ike.get("ikev1_transforms", []))
                    verdicts = {p["name"]: evaluate_policy(observation, p["content"]) for p in snapshot["policies"]}
                    values = set(verdicts.values())
                    observation["verdict"] = ("non_compliant" if "non_compliant" in values else
                                               "compliant" if values == {"compliant"} else "indeterminate")
                    observation["evidence"]["policy_verdicts"] = verdicts
                    observation["target"] = target
                    observations.append(observation)
                    done += 1
                    emit("host_done", {"target": target, "hosts_done": done, "hosts_total": total})
                if cancel.is_set():
                    break
            if cancel.is_set():
                break
        root = Path(payload["export_dir"]) / payload["run_id"]
        root.mkdir(parents=True, exist_ok=True)
        written = []
        rows = [{"target": x["target"], "port": x["port"], "status": x["status"], "ike_version": x["ike_version"],
                 "exchange": x["exchange"], "verdict": x["verdict"],
                 "policy_verdicts": json.dumps(x.get("evidence", {}).get("policy_verdicts", {}), sort_keys=True),
                 **(x["proposal"] or {})} for x in observations]
        for fmt in snapshot["export_formats"]:
            path = root / f"ipsec-results.{fmt}"
            if fmt == "csv":
                stream = io.StringIO(newline="")
                fields = ["target", "port", "status", "ike_version", "exchange", "verdict", "policy_verdicts", "encryption", "key_length_bits", "integrity", "prf", "dh_group"]
                writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
                writer.writeheader(); writer.writerows(rows)
                path.write_text(stream.getvalue())
            elif fmt == "md":
                lines = ["# IPsec / IKE scan results", "", "> Unauthenticated discovery only. ESP/Child SA, authentication, PFS and tunnel operation were not evaluated.", "",
                         "| Target | UDP | Status | IKE | Exchange | Verdict | Policy verdicts | Encryption | Key bits | Integrity | PRF | DH group |", "|---|---:|---|---|---|---|---|---|---:|---|---|---|"]
                lines.extend("| " + " | ".join(str(row.get(k, "")) for k in ("target", "port", "status", "ike_version", "exchange", "verdict", "policy_verdicts", "encryption", "key_length_bits", "integrity", "prf", "dh_group")) + " |" for row in rows)
                path.write_text("\n".join(lines) + "\n")
            elif fmt == "html":
                fields = ("target", "port", "status", "ike_version", "exchange", "verdict", "policy_verdicts", "encryption", "key_length_bits", "integrity", "prf", "dh_group")
                cells = "".join("<tr>" + "".join(f"<td>{html.escape(str(row.get(k, '')))}</td>" for k in fields) + "</tr>" for row in rows)
                headers = ("Target", "UDP", "Status", "IKE", "Exchange", "Verdict", "Policy verdicts", "Encryption", "Key bits", "Integrity", "PRF", "DH group")
                path.write_text("<!doctype html><meta charset='utf-8'><title>IPsec scan</title><h1>IPsec / IKE results</h1><p>Unauthenticated discovery only. ESP/Child SA, authentication, PFS and tunnel operation were not evaluated.</p><table><thead><tr>" + "".join(f"<th>{x}</th>" for x in headers) + f"</tr></thead><tbody>{cells}</tbody></table>")
            else:
                continue
            written.append(str(path))
        outcome_path.write_text(json.dumps({"status": "partial" if cancel.is_set() else "completed",
            "report_model": {"statistics": {"ipsec_observations": len(observations)}}, "ipsec_observations": observations,
            "written_files": written, "scanned_hosts": targets, "skipped_hosts": [],
            "duration_seconds": 0}, default=str))
        return 0
    job, passes = job_from_snapshot(
        payload["snapshot"], payload["run_id"], payload["export_dir"], payload.get("log_file"), payload["max_workers"]
    )
    outcome = execute_scan(job, cancel_event=cancel, on_event=emit, passes=passes)
    ipsec_config = payload["snapshot"].get("ipsec")
    if ipsec_config and "ipsec" in payload["snapshot"].get("enabled_controls", []):
        targets = ipsec_config.get("targets") or sorted({target for item in payload["snapshot"]["passes"] for target in item["targets"]})
        observations, ipsec_files = scan_ipsec(ipsec_config, targets, Path(payload["export_dir"]), payload["run_id"],
                                               payload["snapshot"]["export_formats"], cancel, emit)
        outcome.report_model["statistics"]["ipsec_observations"] = len(observations)
        outcome.written_files.extend(ipsec_files)
        outcome.ipsec_observations = observations
    mail_security_results = []
    mail_cfg = payload["snapshot"].get("mail_security") or {}
    if mail_cfg.get("enabled") and not cancel.is_set():
        emit("phase", {"phase": "mail_security", "hosts": mail_cfg.get("domains", [])})
        from tls_scan_app.services.mail_security import inspect_domains
        mail_security_results = inspect_domains(mail_cfg.get("domains", []), mail_cfg, cancel)
    outcome_path.write_text(json.dumps({
        "status": outcome.status,
        "report_model": outcome.report_model,
        "written_files": outcome.written_files,
        "scanned_hosts": outcome.scanned_hosts,
        "skipped_hosts": outcome.skipped_hosts,
        "duration_seconds": outcome.duration_seconds,
        "mail_security_results": mail_security_results,
        "ipsec_observations": getattr(outcome, "ipsec_observations", []),
    }, default=str))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as error:  # noqa: BLE001 - reported to the parent through stderr
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(2)
