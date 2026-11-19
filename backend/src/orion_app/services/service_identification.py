"""Bounded Nmap service identification on the scan's validated target scope."""
from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

logger = logging.getLogger("orion_app.service_identification")
SOURCE = "Nmap -sV service probe"


def _targets(passes: list[dict], limit: int) -> tuple[list[tuple[str, str]], int]:
    ports_by_target: dict[str, str] = {}
    for item in passes:
        port_spec = str(item.get("ports") or "fast")
        for raw in item.get("targets", []):
            try:
                network = ipaddress.ip_network(raw, strict=False)
                values = (str(network.network_address),) if network.prefixlen == network.max_prefixlen else (str(x) for x in network.hosts())
            except ValueError:
                values = (raw,)
            for value in values:
                ports_by_target.setdefault(value, port_spec)
    ordered = sorted(ports_by_target.items())
    return ordered[:limit], max(0, len(ordered) - limit)


def _service_args(strategy: str, target: str, ports: list[int] | None, port_spec: str,
                  max_parallelism: int, host_timeout: int) -> list[str]:
    args = ["nmap", "-n", "-sV", "--max-retries", "0", "--host-timeout", f"{host_timeout}s",
            "--max-parallelism", str(max_parallelism), "--open", "-oX", "-"]
    args.extend(["--version-light"] if strategy == "fast" else ["--version-intensity", "7"])
    if ports is not None:
        if not ports:
            return []
        args.extend(["-p", ",".join(str(port) for port in ports)])
    elif port_spec == "all":
        args.extend(["-p", "1-65535"])
    elif port_spec == "fast":
        args.extend(["--top-ports", "2000"])
    else:
        # Planner validation ensures target port lists contain only numeric ports/ranges.
        if not all(part.replace("-", "").isdigit() for part in port_spec.split(",")):
            return []
        args.extend(["-p", port_spec])
    args.append(target)
    return args


def parse_nmap_xml(payload: str, requested_target: str, expected_ports: list[int] | None = None) -> list[dict[str, Any]]:
    """Extract truthful, non-compliance service observations from Nmap's XML output."""
    root = ET.fromstring(payload)
    address = next((item.get("addr", "") for item in root.findall(".//host/address")
                    if item.get("addrtype") in {"ipv4", "ipv6"}), requested_target)
    found: dict[int, dict[str, Any]] = {}
    for port_node in root.findall(".//host/ports/port"):
        if port_node.get("protocol") != "tcp":
            continue
        try:
            port = int(port_node.get("portid", ""))
        except ValueError:
            continue
        state = port_node.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port_node.find("service")
        attrs = service.attrib if service is not None else {}
        name, product, version = attrs.get("name", ""), attrs.get("product", ""), attrs.get("version", "")
        try:
            confidence = max(0.0, min(1.0, int(attrs.get("conf", "0")) / 10))
        except ValueError:
            confidence = 0.0
        status = "observed" if product and version and confidence >= 0.8 else "probable" if name or product else "indeterminate"
        found[port] = {"target": requested_target, "address": address, "port": port, "transport": "tcp", "service": name,
                       "product": product, "version": version, "extra_info": attrs.get("extrainfo", ""),
                       "tunnel": attrs.get("tunnel", ""), "method": attrs.get("method", ""),
                       "confidence": confidence, "status": status, "source": SOURCE}
    if expected_ports is not None:
        for port in expected_ports:
            found.setdefault(port, {"target": requested_target, "address": address, "port": port, "transport": "tcp", "service": "",
                                    "product": "", "version": "", "extra_info": "", "tunnel": "",
                                    "method": "", "confidence": 0.0, "status": "indeterminate", "source": SOURCE})
    return [found[port] for port in sorted(found)]


def identify_services(passes: list[dict], settings: dict[str, Any], open_ports: dict[str, list[int]] | None = None,
                      scope_names_by_ip: dict[str, list[str]] | None = None,
                      cancel=None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run fixed Nmap probes with explicit target/port, worker, result and wall-clock bounds."""
    if not settings.get("enabled"):
        return [], {"enabled": False}
    strategy = settings.get("strategy", "fast")
    max_targets = max(1, min(128, int(settings.get("max_targets", 64))))
    max_services = max(1, min(500, int(settings.get("max_services", 200))))
    timeout = max(5, min(90, int(settings.get("timeout_seconds", 45))))
    parallelism = max(1, min(10, int(settings.get("max_parallelism", 5))))
    targets, skipped_targets = _targets(passes, max_targets)
    not_tested_targets: list[str] = []
    if open_ports is not None:
        # When the TLS engine already performed discovery, its IP-keyed open-port map is the
        # authoritative intersection of the selected targets and their requested port scopes.
        scoped = [target for target, _ in targets]
        targets = [(target, "") for target, ports in sorted(open_ports.items()) if ports][:max_targets]
        tested_targets = {target for target, _ in targets}
        not_tested_targets = [target for target in scoped if target not in tested_targets]
        skipped_targets = max(skipped_targets, len(open_ports) - len(targets))
    deadline = time.monotonic() + timeout

    def scan_one(target: str, port_spec: str) -> tuple[list[dict[str, Any]], bool]:
        if cancel is not None and cancel.is_set():
            return [], False
        remaining = max(1, int(deadline - time.monotonic()))
        ports = sorted(set(int(port) for port in (open_ports or {}).get(target, []) if 1 <= int(port) <= 65535)) if open_ports is not None else None
        command = _service_args(strategy, target, ports, port_spec, parallelism, remaining)
        if not command:
            return [], False
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=remaining, check=False,
                                  start_new_session=True)
            if proc.returncode != 0 and not proc.stdout.strip():
                return [], False
            rows = parse_nmap_xml(proc.stdout, target, ports)
            aliases = (scope_names_by_ip or {}).get(target, [])
            for row in rows:
                if aliases:
                    row["scope_targets"] = aliases
            return rows, False
        except subprocess.TimeoutExpired:
            return [], True
        except (OSError, ET.ParseError, ValueError):
            logger.exception("Nmap service identification failed for target=%s", target)
            return [], False

    results: list[dict[str, Any]] = []
    timed_out = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as executor:
        futures = {executor.submit(scan_one, target, port_spec): target for target, port_spec in targets}
        try:
            completed = concurrent.futures.as_completed(futures, timeout=timeout + 1)
            for future in completed:
                if cancel is not None and cancel.is_set():
                    for pending in futures:
                        pending.cancel()
                    break
                try:
                    rows, hit_timeout = future.result()
                    results.extend(rows)
                    timed_out = timed_out or hit_timeout
                except concurrent.futures.TimeoutError:
                    timed_out = True
        except concurrent.futures.TimeoutError:
            timed_out = True
        for pending in futures:
            if not pending.done():
                pending.cancel()

    results.sort(key=lambda item: (item["target"], item["port"]))
    if open_ports is not None:
        results.extend({"target": target, "address": target, "port": None, "transport": "tcp", "service": "",
                        "product": "", "version": "", "extra_info": "No open TCP ports were available for service probes",
                        "tunnel": "", "method": "", "confidence": 0.0, "status": "not_tested", "source": SOURCE}
                       for target in not_tested_targets)
    truncated = len(results) > max_services
    if truncated:
        results = results[:max_services]
    if skipped_targets:
        results.append({"target": "", "port": None, "transport": "tcp", "service": "", "product": "", "version": "",
                       "extra_info": f"{skipped_targets} target(s) exceeded the profile target limit", "tunnel": "", "method": "",
                       "confidence": 0.0, "status": "not_tested", "source": SOURCE})
    if timed_out or (time.monotonic() >= deadline and len(results) == 0):
        results.append({"target": "", "port": None, "transport": "tcp", "service": "", "product": "", "version": "",
                       "extra_info": "Service identification time budget reached", "tunnel": "", "method": "",
                       "confidence": 0.0, "status": "indeterminate", "source": SOURCE})
    return results, {"enabled": True, "strategy": strategy, "targets_tested": len(targets), "skipped_targets": skipped_targets,
                     "max_services": max_services, "truncated": truncated, "timed_out": timed_out, "source": SOURCE}


def write_report(observations: list[dict[str, Any]], export_dir: Path, run_id: str, formats: list[str]) -> list[str]:
    if "csv" not in formats:
        return []
    import csv
    import io

    path = export_dir / run_id / "service-identification.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ("target", "address", "scope_targets", "port", "transport", "service", "product", "version", "extra_info", "tunnel", "method", "confidence", "status", "source")
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows({**observation, "scope_targets": ";".join(observation.get("scope_targets") or [])}
                      for observation in observations)
    path.write_text(stream.getvalue(), encoding="utf-8")
    return [str(path)]
