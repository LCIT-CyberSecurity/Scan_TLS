"""Bounded, unauthenticated SSH handshake auditing through Debian's ssh-audit CLI."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any


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
        err = result.stderr[:1000]
        status = "filtered" if any(term in err.lower() for term in ("refused", "unreachable", "no route")) else "error"
        return {"status": status, "evidence": {"engine": "ssh-audit", "exit_code": result.returncode, "error": err}}
    if isinstance(parsed, list):
        parsed = parsed[0] if parsed else {}
    if not isinstance(parsed, dict):
        return {"status": "error", "evidence": {"engine": "ssh-audit", "error": "unexpected JSON result"}}
    observation = parse_ssh_audit_json(parsed)
    observation["evidence"] |= {"exit_code": result.returncode, "stderr": result.stderr[:1000]}
    return observation


# Offers that are broken or weak whatever the policy: SHA-1, MD5, CBC, 3DES/RC4/Blowfish/CAST, DSA and SHA-1 RSA
# signatures, truncated or 64-bit MACs, "none", and SSHv1. A policy violation matching one of them is high severity;
# a strong algorithm that the policy simply does not list is medium.
WEAK_SSH_OFFER = re.compile(r"sha1|md5|-cbc|3des|arcfour|rc4|blowfish|cast128|ssh-dss|^ssh-rsa(-cert|$)|umac-64|-96($|@)|^none$|^SSH-1")
SSH_FINDING_CATEGORIES = (
    # (observation key, policy key, finding id stem, title label, sshd_config directive)
    ("protocol_versions", "allowed_protocols", "PROTOCOL", "Protocol Version", "the server version (Protocol)"),
    ("key_exchange", "allowed_kex", "KEX", "Key Exchange", "KexAlgorithms"),
    ("encryption", "allowed_encryption", "CIPHER", "Cipher", "Ciphers"),
    ("mac", "allowed_macs", "MAC", "MAC", "MACs"),
    ("host_key", "allowed_host_keys", "HOST_KEY", "Host Key Algorithm", "HostKeyAlgorithms and HostKey"),
)


def findings_from_observations(observations: list[dict[str, Any]], policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn the policy violations of observed SSH servers into run findings, one per problem type.

    Endpoints are `<target>:<port>/tcp`. Only what was observed is reported: an indeterminate observation (missing
    algorithms or RSA size) produces no finding."""
    grouped: dict[str, dict[str, Any]] = {}

    def add(finding_id: str, title: str, severity: str, endpoint: str, offers: list[str], remediation: str) -> None:
        item = grouped.setdefault(finding_id, {"finding_id": finding_id, "title": title, "category": "SSH", "severity": severity,
                                               "status": "KO", "remediation": remediation, "by_endpoint": {}})
        item["by_endpoint"].setdefault(endpoint, set()).update(offers)

    for observation in observations:
        if observation.get("status") != "observed":
            continue
        endpoint = f"{observation['target']}:{observation['port']}/tcp"
        algorithms = observation.get("algorithms") or {}
        for policy in policies:
            content = policy["content"]
            for key, allowed, stem, label, directive in SSH_FINDING_CATEGORIES:
                rejected = sorted(set(algorithms.get(key) or []) - set(content[allowed]))
                weak = [name for name in rejected if WEAK_SSH_OFFER.search(name)]
                strong = [name for name in rejected if name not in weak]
                remediation = (f"Remove the listed offers from {directive} in sshd_config and keep only those the SSH policy allows; "
                               "reload sshd and scan again.")
                if weak:
                    add(f"SSH_WEAK_{stem}", f"Weak SSH {label} Offered", "high", endpoint, weak, remediation)
                if strong:
                    add(f"SSH_{stem}_NOT_ALLOWED", f"SSH {label} Not Allowed by Policy", "medium", endpoint, strong, remediation)
            short = sorted({size for size in observation.get("rsa_key_sizes") or [] if size < content["minimum_rsa_bits"]})
            if short:
                add("SSH_RSA_KEY_TOO_SHORT", "SSH RSA Host Key Too Short", "high", endpoint, [f"{size} bits" for size in short],
                    f"Replace the RSA host key with one of at least {content['minimum_rsa_bits']} bits (ssh-keygen -t rsa -b 4096), "
                    "or serve only the host key types the policy allows.")
    findings = []
    for item in grouped.values():
        by_endpoint = item.pop("by_endpoint")
        item["affected_endpoint_ids"] = sorted(by_endpoint)
        item["evidence"] = "; ".join(f"{endpoint}: {', '.join(sorted(offers))}" for endpoint, offers in sorted(by_endpoint.items()))
        findings.append(item)
    return sorted(findings, key=lambda f: f["finding_id"])
