"""Bounded, unauthenticated SSH handshake auditing through Debian's ssh-audit CLI."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
# ssh-audit failures meaning nothing speaks SSH on the port (closed, filtered, unreachable or another protocol).
# The caller reports these as "no SSH service", not as a probe error; DNS failures stay errors.
NO_SSH_SERVICE_MESSAGES = ("cannot connect to", "did not receive banner")


def validate_ssh_profile(content: dict[str, Any]) -> None:
    if not isinstance(content, dict) or set(content) != {"ssh"} or not isinstance(content["ssh"], dict):
        raise ValueError("SSH profile section must contain only ssh settings")
    ssh = content["ssh"]
    if set(ssh) - {"ports", "timeout_seconds", "preset", "max_targets", "retries"}:
        raise ValueError("unsupported SSH profile fields")
    ports = ssh.get("ports", [22])
    if (not isinstance(ports, list) or not ports or len(ports) > 32
            or any(not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535 for p in ports)
            or len(set(ports)) != len(ports)):
        raise ValueError("SSH ports must be 1–32 unique TCP port numbers")
    timeout = ssh.get("timeout_seconds", 2)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 5:
        raise ValueError("SSH timeout_seconds must be between 1 and 5")
    if ssh.get("preset", "quick") not in {"quick", "deep"}:
        raise ValueError("SSH preset must be quick or deep")
    max_targets = ssh.get("max_targets", 256)
    if not isinstance(max_targets, int) or isinstance(max_targets, bool) or not 1 <= max_targets <= 1024:
        raise ValueError("SSH max_targets must be between 1 and 1024")
    retries = ssh.get("retries", 0)
    if not isinstance(retries, int) or isinstance(retries, bool) or not 0 <= retries <= 1:
        raise ValueError("SSH retries must be between 0 and 1")


def validate_ssh_policy(content: dict[str, Any]) -> None:
    fields = {"allowed_protocols", "allowed_kex", "allowed_encryption", "allowed_macs", "allowed_host_keys", "minimum_rsa_bits"}
    if not isinstance(content, dict) or set(content) != fields:
        raise ValueError(f"SSH policy fields must be exactly {sorted(fields)}")
    for key in fields - {"minimum_rsa_bits"}:
        values = content[key]
        if not isinstance(values, list) or not values or not all(isinstance(v, str) and v for v in values):
            raise ValueError(f"{key} must be a non-empty list of strings")
    bits = content["minimum_rsa_bits"]
    if not isinstance(bits, int) or isinstance(bits, bool) or not 1024 <= bits <= 16384:
        raise ValueError("minimum_rsa_bits must be between 1024 and 16384")


def _names(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        found = []
        for item in value:
            if isinstance(item, str) and item:
                found.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("algorithm") or item.get("type")
                if isinstance(name, str) and name:
                    found.append(name)
        return list(dict.fromkeys(found))
    if isinstance(value, dict):
        if "algorithms" in value:
            return _names(value["algorithms"])
        if "name" in value or "algorithm" in value:
            return _names([value])
        return list(dict.fromkeys(name for nested in value.values() for name in _names(nested)))
    return []


def parse_ssh_audit_json(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize ssh-audit's JSON output; missing evidence remains absent, never compliant."""
    banner_raw = raw.get("banner") or raw.get("protocol") or {}
    if isinstance(banner_raw, dict):
        protocol = banner_raw.get("protocol") or banner_raw.get("version") or ""
        software = banner_raw.get("software") or ""
        banner = str(banner_raw.get("raw") or " ".join(str(v) for v in (protocol, software) if v))
        if banner.startswith("SSH-"):
            protocol = banner.split("-", 2)[1]
            protocol = f"SSH-{protocol}"
        elif protocol and not str(protocol).startswith("SSH-"):
            protocol = f"SSH-{protocol}"
    else:
        banner = str(banner_raw)
        protocol = banner.split("-", 2)[1] if banner.startswith("SSH-") and len(banner.split("-", 2)) > 1 else ""
        software = ""
    algorithms = {
        "protocol_versions": [str(protocol)] if protocol else [],
        "key_exchange": _names(raw.get("kex") or raw.get("key exchange") or raw.get("key_exchange")),
        "encryption": _names(raw.get("enc") or raw.get("encryption") or raw.get("ciphers")),
        "mac": _names(raw.get("mac") or raw.get("macs")),
        "host_key": _names(raw.get("key") or raw.get("host keys") or raw.get("host_keys")),
    }
    sizes = raw.get("host_key_sizes") or raw.get("hostkey_sizes") or {}
    rsa_sizes = [int(v) for k, v in sizes.items() if "rsa" in str(k).lower() and str(v).isdigit()] if isinstance(sizes, dict) else []
    def collect_rsa_sizes(value: Any) -> None:
        if isinstance(value, dict):
            label = " ".join(str(value.get(key, "")) for key in ("name", "algorithm", "type", "key_type"))
            size = value.get("bits") or value.get("size") or value.get("key_size")
            if "rsa" in label.lower() and isinstance(size, int) and not isinstance(size, bool):
                rsa_sizes.append(size)
            for nested in value.values():
                collect_rsa_sizes(nested)
        elif isinstance(value, list):
            for nested in value:
                collect_rsa_sizes(nested)
    collect_rsa_sizes(raw.get("key") or raw.get("host keys") or raw.get("host_keys"))
    observed = bool(banner or any(algorithms.values()))
    return {
        "status": "observed" if observed else "error",
        "banner": banner[:255],
        "software": str(software)[:120],
        "algorithms": algorithms,
        "host_keys": algorithms["host_key"],
        "fingerprints": raw.get("fingerprints") if isinstance(raw.get("fingerprints"), dict) else {},
        "rsa_key_sizes": list(dict.fromkeys(rsa_sizes)),
        "evidence": {"engine": "ssh-audit", "engine_version": str(raw.get("version", ""))[:80],
                     "rsa_key_sizes": list(dict.fromkeys(rsa_sizes)),
                     "recommendations": raw.get("recommendations", []), "notes": raw.get("notes", {})},
    }


def evaluate_ssh_policy(observation: dict[str, Any], policy: dict[str, Any]) -> str:
    if observation.get("status") != "observed":
        return "indeterminate"
    algorithms = observation.get("algorithms") or {}
    mapping = (("protocol_versions", "allowed_protocols"), ("key_exchange", "allowed_kex"),
               ("encryption", "allowed_encryption"), ("mac", "allowed_macs"), ("host_key", "allowed_host_keys"))
    if any(not algorithms.get(key) for key, _ in mapping):
        return "indeterminate"
    if any(set(algorithms[key]) - set(policy[allowed]) for key, allowed in mapping):
        return "non_compliant"
    host_keys = algorithms.get("host_key", [])
    rsa_offered = any("rsa" in key.lower() for key in host_keys)
    sizes = observation.get("rsa_key_sizes") or []
    if rsa_offered and not sizes:
        return "indeterminate"
    if sizes and any(size < policy["minimum_rsa_bits"] for size in sizes):
        return "non_compliant"
    return "compliant"


def audit_target(target: str, port: int, timeout_seconds: int = 2) -> dict[str, Any]:
    """Run one read-only protocol audit; intentionally excludes DHEat/rate tests and auth probes."""
    binary = shutil.which("ssh-audit")
    if not binary:
        return {"status": "error", "evidence": {"error": "ssh-audit is not installed"}}
    args = [binary, "--json", "--port", str(port), "--timeout", str(timeout_seconds), "--skip-rate-test", target]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout_seconds + 2, check=False,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_COLOR": "1"})
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "evidence": {"engine": "ssh-audit", "timeout_seconds": timeout_seconds}}
    output = result.stdout.strip()
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        # ssh-audit prints its "[exception] …" line on stdout, in colour, instead of JSON
        err = ANSI_ESCAPE.sub("", f"{result.stdout}\n{result.stderr}").strip()[:1000]
        status = "no_service" if any(term in err for term in NO_SSH_SERVICE_MESSAGES) else "error"
        return {"status": status, "evidence": {"engine": "ssh-audit", "exit_code": result.returncode, "error": err}}
    if isinstance(parsed, list):
        parsed = parsed[0] if parsed else {}
    if not isinstance(parsed, dict):
        return {"status": "error", "evidence": {"engine": "ssh-audit", "error": "unexpected JSON result"}}
    observation = parse_ssh_audit_json(parsed)
    observation["evidence"] |= {"exit_code": result.returncode, "stderr": result.stderr[:1000]}
    return observation
