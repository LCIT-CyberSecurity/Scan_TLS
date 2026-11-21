"""Scan subprocess: runs the engine for one snapshot, with no database access.

Usage: python -m orion_app.workers.child <snapshot.json> <outcome.json>
Emits one JSON event per line on stdout. SIGTERM requests a cooperative cancellation: hosts not yet
started are skipped and the partial results are still written.
"""
from __future__ import annotations

import csv
import html
import io
import json
import signal
import sys
import threading
from pathlib import Path

from orion_app.services.ipsec import evaluate_policy, probe
from orion_app.services.planner import job_from_snapshot
from orion_app.services.quic_scan import scan as scan_quic, write_csv as write_quic_report
from orion_app.services.service_identification import identify_services
from orion_app.services.service_identification import write_report as write_service_report
from orion_app.services.ssh_audit import audit_target, evaluate_ssh_policy
from tls_scanner.runner import execute_scan


def emit(name: str, data: dict) -> None:
    print(json.dumps({"event": name, **data}), flush=True)


def scan_ssh(config: dict, cancel, emit):
    """Bounded unauthenticated ssh-audit probes. No credentials or rate tests are used."""
    settings, policies = config["settings"], config.get("policies", [])
    observations = []
    targets = config.get("targets", [])[:int(settings.get("max_targets", 256))]
    ports = settings.get("ports", [22])
    if settings.get("preset", "quick") == "quick":
        ports = ports[:1]
    total, done = len(targets) * len(ports), 0
    for target in targets:
        for port in ports:
            if cancel.is_set():
                break
            emit("phase", {"phase": "ssh_audit", "hosts": targets})
            observation = audit_target(target, int(port), int(settings.get("timeout_seconds", 2)))
            retries = int(settings.get("retries", 0))
            for _ in range(retries):
                if observation.get("status") not in {"timeout", "no_service"} or cancel.is_set():
                    break
                observation = audit_target(target, int(port), int(settings.get("timeout_seconds", 2)))
            done += 1
            if observation.get("status") == "no_service":
                # no SSH server answered: nothing to audit, so nothing is reported for this port
                emit("host_done", {"target": target, "hosts_done": done, "hosts_total": total})
                continue
            verdicts = {p["name"]: evaluate_ssh_policy(observation, p["content"]) for p in policies}
            values = set(verdicts.values())
            observation.update({"target": target, "port": int(port), "verdict": (
                "non_compliant" if "non_compliant" in values else "compliant" if values == {"compliant"} else "indeterminate")})
            observation.setdefault("evidence", {})["policy_verdicts"] = verdicts
            observations.append(observation)
            emit("host_done", {"target": target, "hosts_done": done, "hosts_total": total})
        if cancel.is_set():
            break
    return observations, targets


def write_ssh_reports(observations: list[dict], export_dir: Path, run_id: str, formats: list[str]):
    root = export_dir / run_id
    root.mkdir(parents=True, exist_ok=True)
    files = []
    fields = ("target", "port", "status", "verdict", "banner", "protocol_versions", "key_exchange", "encryption", "mac", "host_key", "fingerprints")
    for fmt in formats:
        path = root / f"ssh-results.{fmt}"
        rows = [{"target": x["target"], "port": x["port"], "status": x["status"], "verdict": x["verdict"], "banner": x.get("banner", ""),
                 **{k: ", ".join((x.get("algorithms") or {}).get(src, [])) for k, src in (("protocol_versions", "protocol_versions"), ("key_exchange", "key_exchange"), ("encryption", "encryption"), ("mac", "mac"), ("host_key", "host_key"))},
                 "fingerprints": json.dumps(x.get("fingerprints") or {}, sort_keys=True)}
                for x in observations]
        if fmt == "csv":
            stream = io.StringIO(newline="")
            writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader(); writer.writerows(rows)
            path.write_text(stream.getvalue(), encoding="utf-8")
        elif fmt == "md":
            lines = ["# SSH audit results", "", "> Unauthenticated protocol audit. No password, key or rate-limit tests were performed.", "",
                     "| Target | Port | Status | Verdict | Banner | Algorithms |", "|---|---:|---|---|---|---|"]
            lines.extend(f"| {r['target']} | {r['port']} | {r['status']} | {r['verdict']} | {r['banner']} | {', '.join(r['key_exchange'] + r['encryption'] + r['mac'] + r['host_key'])} |" for r in rows)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        elif fmt == "html":
            import html
            head = "".join(f"<th>{html.escape(k.replace('_', ' ').title())}</th>" for k in fields)
            body = "".join("<tr>" + "".join(f"<td>{html.escape(str(r.get(k, '')))}</td>" for k in fields) + "</tr>" for r in rows)
            path.write_text("<!doctype html><meta charset='utf-8'><title>SSH audit</title><h1>SSH audit results</h1><p>Unauthenticated protocol audit; no credentials or rate tests were used.</p><table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>", encoding="utf-8")
        else:
            continue
        files.append(str(path))
    return files


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
    def scan_services(snapshot: dict, passes: list[dict], open_ports: dict[str, list[int]] | None = None,
                      scope_names_by_ip: dict[str, list[str]] | None = None):
        config = snapshot.get("service_identification")
        if not config or not config.get("enabled") or cancel.is_set():
            return [], []
        emit("phase", {"phase": "service_identification", "hosts": sorted({t for p in passes for t in p["targets"]})})
        observations, _metadata = identify_services(passes, config, open_ports=open_ports,
                                                     scope_names_by_ip=scope_names_by_ip, cancel=cancel)
        files = write_service_report(observations, Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"])
        return observations, files
    def scan_quic_for_snapshot(snapshot: dict):
        config = snapshot.get("quic")
        if not config or not config.get("enabled") or cancel.is_set():
            return [], []
        emit("phase", {"phase": "quic_probe", "hosts": sorted({t for p in snapshot["passes"] for t in p["targets"]})})
        observations = scan_quic(config, snapshot["passes"], snapshot.get("tls_policies") or snapshot.get("policies") or [], cancel)
        files = write_quic_report(observations, Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"])
        return observations, files
    if payload["snapshot"].get("control_type") == "ssh":
        snapshot = payload["snapshot"]
        observations, targets = scan_ssh(snapshot["ssh"], cancel, emit)
        written = write_ssh_reports(observations, Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"])
        service_observations, service_files = scan_services(snapshot, snapshot["passes"])
        outcome_path.write_text(json.dumps({"status": "partial" if cancel.is_set() else "completed",
            "report_model": {"statistics": {"ssh_observations": len(observations), "service_observations": len(service_observations)}}, "ssh_observations": observations,
            "service_observations": service_observations,
            "written_files": [*written, *service_files], "scanned_hosts": targets, "skipped_hosts": [], "duration_seconds": 0}, default=str))
        return 0
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
        service_observations, service_files = scan_services(snapshot, snapshot["passes"])
        outcome_path.write_text(json.dumps({"status": "partial" if cancel.is_set() else "completed",
            "report_model": {"statistics": {"ipsec_observations": len(observations), "service_observations": len(service_observations)}}, "ipsec_observations": observations,
            "service_observations": service_observations,
            "written_files": [*written, *service_files], "scanned_hosts": targets, "skipped_hosts": [],
            "duration_seconds": 0}, default=str))
        return 0
    if "tls" not in payload["snapshot"].get("enabled_controls", []) and "ipsec" in payload["snapshot"].get("enabled_controls", []):
        snapshot = payload["snapshot"]
        ike_config = snapshot["ipsec"]
        ike_targets = ike_config.get("targets") or sorted({t for p in snapshot["passes"] for t in p["targets"]})
        ike_observations, ike_files = scan_ipsec(ike_config, ike_targets, Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"], cancel, emit)
        ssh_observations, ssh_files, ssh_targets = [], [], []
        if snapshot.get("ssh") and "ssh" in snapshot["enabled_controls"] and not cancel.is_set():
            ssh_observations, ssh_targets = scan_ssh(snapshot["ssh"], cancel, emit)
            ssh_files = write_ssh_reports(ssh_observations, Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"])
        service_observations, service_files = scan_services(snapshot, snapshot["passes"])
        outcome_path.write_text(json.dumps({"status": "partial" if cancel.is_set() else "completed",
            "report_model": {"statistics": {"ipsec_observations": len(ike_observations), "ssh_observations": len(ssh_observations), "service_observations": len(service_observations)}},
            "ipsec_observations": ike_observations, "ssh_observations": ssh_observations,
            "service_observations": service_observations,
            "written_files": [*ike_files, *ssh_files, *service_files], "scanned_hosts": sorted(set(ike_targets + ssh_targets)),
            "skipped_hosts": [], "duration_seconds": 0}, default=str))
        return 0
    job, passes = job_from_snapshot(
        payload["snapshot"], payload["run_id"], payload["export_dir"], payload.get("log_file"), payload["max_workers"]
    )
    service_config = payload["snapshot"].get("service_identification") or {}
    outcome = execute_scan(job, cancel_event=cancel, on_event=emit, passes=passes,
                           collect_open_ports=bool(service_config.get("enabled")))
    service_observations, service_files = scan_services(payload["snapshot"], payload["snapshot"]["passes"],
                                                        open_ports=getattr(outcome, "open_ports", {}) if service_config.get("enabled") else None,
                                                        scope_names_by_ip=getattr(outcome, "scope_names_by_ip", {}))
    if service_observations:
        outcome.report_model["statistics"]["service_observations"] = len(service_observations)
        outcome.written_files.extend(service_files)
        outcome.service_observations = service_observations
    quic_observations, quic_files = scan_quic_for_snapshot(payload["snapshot"])
    if quic_observations:
        outcome.written_files.extend(quic_files)
        outcome.quic_observations = quic_observations
    ipsec_config = payload["snapshot"].get("ipsec")
    if ipsec_config and "ipsec" in payload["snapshot"].get("enabled_controls", []):
        targets = ipsec_config.get("targets") or sorted({target for item in payload["snapshot"]["passes"] for target in item["targets"]})
        observations, ipsec_files = scan_ipsec(ipsec_config, targets, Path(payload["export_dir"]), payload["run_id"],
                                               payload["snapshot"]["export_formats"], cancel, emit)
        outcome.report_model["statistics"]["ipsec_observations"] = len(observations)
        outcome.written_files.extend(ipsec_files)
        outcome.ipsec_observations = observations
    ssh_config = payload["snapshot"].get("ssh")
    if ssh_config and "ssh" in payload["snapshot"].get("enabled_controls", []) and not cancel.is_set():
        observations, _ = scan_ssh(ssh_config, cancel, emit)
        outcome.report_model["statistics"]["ssh_observations"] = len(observations)
        outcome.written_files.extend(write_ssh_reports(observations, Path(payload["export_dir"]), payload["run_id"],
                                                       payload["snapshot"]["export_formats"]))
        outcome.ssh_observations = observations
    mail_security_results = []
    mail_cfg = payload["snapshot"].get("mail_security") or {}
    if mail_cfg.get("enabled") and not cancel.is_set():
        emit("phase", {"phase": "mail_security", "hosts": mail_cfg.get("domains", [])})
        from orion_app.services.mail_security import inspect_domains
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
        "ssh_observations": getattr(outcome, "ssh_observations", []),
        "service_observations": getattr(outcome, "service_observations", service_observations),
        "quic_observations": getattr(outcome, "quic_observations", quic_observations),
    }, default=str))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as error:  # noqa: BLE001 - reported to the parent through stderr
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(2)
