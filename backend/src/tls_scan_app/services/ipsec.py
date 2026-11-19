"""Constrained, unauthenticated IKE discovery and IPsec policy evaluation."""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any


def validate_ipsec_profile(content: dict[str, Any]) -> None:
    if set(content) != {"ike"} or not isinstance(content.get("ike"), dict):
        raise ValueError("IPsec profiles must contain only the ike section")
    ike = content["ike"]
    if set(ike) - {"versions", "ports", "nat_t", "timeout_ms", "retries", "aggressive_mode", "ikev1_transforms"}:
        raise ValueError("unsupported IPsec profile fields")
    if (not isinstance(ike.get("versions"), list) or not ike["versions"]
            or not all(isinstance(v, str) for v in ike["versions"]) or set(ike["versions"]) - {"IKEv1", "IKEv2"}):
        raise ValueError("versions must contain IKEv1 and/or IKEv2")
    if len(set(ike["versions"])) != len(ike["versions"]):
        raise ValueError("versions must not contain duplicates")
    if (not isinstance(ike.get("ports"), list) or not ike["ports"]
            or not all(isinstance(p, int) and not isinstance(p, bool) for p in ike["ports"])
            or set(ike["ports"]) - {500, 4500}):
        raise ValueError("ports must contain UDP 500 and/or 4500")
    if len(set(ike["ports"])) != len(ike["ports"]):
        raise ValueError("ports must not contain duplicates")
    if not isinstance(ike.get("nat_t", True), bool):
        raise ValueError("nat_t must be true or false")
    if not isinstance(ike.get("aggressive_mode", False), bool):
        raise ValueError("aggressive_mode must be true or false")
    if not isinstance(ike.get("timeout_ms", 1000), int) or isinstance(ike.get("timeout_ms", 1000), bool) or not 100 <= ike.get("timeout_ms", 1000) <= 5000:
        raise ValueError("timeout_ms must be between 100 and 5000")
    if not isinstance(ike.get("retries", 0), int) or isinstance(ike.get("retries", 0), bool) or not 0 <= ike.get("retries", 0) <= 2:
        raise ValueError("retries must be between 0 and 2")
    if ike.get("aggressive_mode", False):
        raise ValueError("IKEv1 aggressive mode is not supported")
    transforms = ike.get("ikev1_transforms", [])
    if not isinstance(transforms, list) or len(transforms) > 4:
        raise ValueError("ikev1_transforms must contain at most four transforms")
    for transform in transforms:
        match = re.fullmatch(r"(1|3|5|7|8|9|11|12)(?:/(128|192|256))?,(1|2|4),(1|3),(1|2|5|14|15|16|17|18)", str(transform))
        if not match or (match.group(2) and match.group(1) != "7"):
            raise ValueError("each IKEv1 transform must use supported enc/hash/auth/DH IDs; key lengths apply to AES only")
    if len(set(transforms)) != len(transforms):
        raise ValueError("ikev1_transforms must not contain duplicates")


def validate_ipsec_policy(content: dict[str, Any]) -> None:
    fields = {"allowed_versions", "allowed_encryption", "allowed_integrity", "allowed_prf", "allowed_dh_groups"}
    if set(content) != fields:
        raise ValueError(f"IPsec policy fields must be exactly {sorted(fields)}")
    for key in fields:
        value = content[key]
        if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
            raise ValueError(f"{key} must be a non-empty list of strings")
    if set(content["allowed_versions"]) - {"IKEv1", "IKEv2"}:
        raise ValueError("allowed_versions must contain IKEv1 and/or IKEv2")


def evaluate_policy(observation: dict[str, Any], policy: dict[str, Any]) -> str:
    """Only observed accepted transforms can decide compliance; unanswered/partial tests stay unknown."""
    if observation.get("status") != "observed":
        return "indeterminate"
    proposal = observation.get("proposal") or {}
    if not observation.get("ike_version") or not proposal:
        return "indeterminate"
    checks = (("ike_version", "allowed_versions"), ("encryption", "allowed_encryption"),
              ("integrity", "allowed_integrity"), ("prf", "allowed_prf"), ("dh_group", "allowed_dh_groups"))
    compared = 0
    missing = False
    for field, policy_field in checks:
        value = observation.get(field) if field == "ike_version" else proposal.get(field)
        if value is None:
            missing = True
            continue
        compared += 1
        allowed = policy.get(policy_field, [])
        def canonical(candidate: str) -> str:
            token = re.sub(r"[^A-Z0-9]+", "_", candidate.upper()).strip("_")
            token = re.sub(r"_+", "_", token)
            if field == "encryption" and token in {"AES_GCM_8", "AES_GCM_12", "AES_GCM_16"}:
                return "AES_GCM"
            if field == "integrity":
                token = token.removeprefix("HMAC_")
                if token in {"SHA256", "SHA_256", "SHA2_256", "SHA256_128", "SHA2_256_128"}:
                    token = "SHA2_256"
                elif token in {"SHA384", "SHA_384", "SHA2_384", "SHA384_192", "SHA2_384_192"}:
                    token = "SHA2_384"
                elif token in {"SHA512", "SHA_512", "SHA2_512", "SHA512_256", "SHA2_512_256"}:
                    token = "SHA2_512"
                elif token in {"SHA1", "SHA_1", "SHA1_96"}:
                    token = "SHA1"
            if field == "prf":
                token = token.removeprefix("PRF_")
            if field == "dh_group":
                match = re.search(r"(?:^|_)MODP_?(\d+)$", token)
                if match:
                    token = f"MODP_{match.group(1)}"
            return token

        if canonical(str(value)) not in {canonical(str(v)) for v in allowed}:
            return "non_compliant"
    return "compliant" if compared and not missing else "indeterminate"


def _field(line: str, name: str) -> str | None:
    match = re.search(rf"\b{re.escape(name)}\s*=\s*([^,\s)]+)", line, re.I)
    return match.group(1) if match else None


def parse_ike_scan(stdout: str, version: str, port: int) -> dict[str, Any]:
    """Parse only ike-scan's decoded response line; malformed/no response never implies compliance."""
    lines = [line for line in stdout.splitlines() if "HDR=(" in line or "SA=(" in line]
    if not lines:
        return {"status": "timeout", "port": port, "ike_version": "", "exchange": "", "proposal": {}, "evidence": {}}
    line = lines[0]
    version_match = re.search(r"\bversion\s*=\s*(\d+)\.", line, re.I)
    if not version_match or version_match.group(1) not in {"1", "2"}:
        return {"status": "error", "port": port, "ike_version": "", "exchange": "", "proposal": {},
                "evidence": {"error": "IKE response has no supported version field", "response": line[:1200]}}
    observed_version = "IKEv1" if version_match.group(1) == "1" else "IKEv2"
    proposal = {}
    for output, names in (("encryption", ("encryption",)), ("integrity", ("integrity", "hash")),
                          ("prf", ("prf",)), ("authentication", ("auth",)), ("dh_group", ("group",))):
        value = next((parsed for name in names if (parsed := _field(line, name)) is not None), None)
        if value is not None:
            proposal[output] = value
    key_length = re.search(r"\bkey\s+length\s*=\s*(\d+)", line, re.I)
    if key_length:
        proposal["key_length_bits"] = key_length.group(1)
    return {"status": "observed", "port": port, "ike_version": observed_version,
            "exchange": "IKE_SA_INIT" if observed_version == "IKEv2" else "Main Mode",
            "proposal": proposal, "evidence": {"decoder": "ike-scan", "response": line[:1200],
                                                  "proposal_scope": "one response; not an exhaustive list"}}


def probe(target: str, version: str, port: int, timeout_ms: int = 1000, retries: int = 0, nat_t: bool = True,
          ikev1_transforms: list[str] | None = None) -> dict[str, Any]:
    """Run one bounded, unauthenticated probe via ike-scan; never requests aggressive mode."""
    binary = shutil.which("ike-scan")
    if not binary:
        return {"status": "error", "port": port, "ike_version": "", "exchange": "", "proposal": {},
                "evidence": {"error": "ike-scan is not installed"}}
    args = [binary, f"--timeout={timeout_ms}", f"--retry={retries + 1}", "--bandwidth=1000"]
    if port == 4500 and nat_t:
        args.append("--nat-t")
    else:
        args.extend((f"--dport={port}", "--sport=0"))
    if version == "IKEv2":
        args.append("--ikev2")
    elif ikev1_transforms:
        args.extend(f"--trans={value}" for value in ikev1_transforms)
    args.append(target)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=(timeout_ms * (retries + 1) / 1000) + 2,
                                check=False, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "port": port, "ike_version": "", "exchange": "", "proposal": {}, "evidence": {}}
    if result.returncode not in (0, 1):
        return {"status": "error", "port": port, "ike_version": "", "exchange": "", "proposal": {},
                "evidence": {"error": (result.stderr or "ike-scan failed")[:500]}}
    observation = parse_ike_scan(result.stdout, version, port)
    if observation["status"] == "timeout" and "Received 0 response" in result.stdout:
        observation["status"] = "indeterminate"
    return observation
