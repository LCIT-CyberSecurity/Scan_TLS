"""
B1 - ECDHE groups and B2 - FFDHE groups / Diffie-Hellman parameters.

Method: `openssl s_client` offering one group at a time. A completed handshake proves the server
accepts that group (per TLS version tested); a refusal only means it was not accepted in that probe.
The result is therefore a list of *proven* groups, never presented as the complete server list.
"""

from __future__ import annotations

import re

from .contracts import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, CheckContext, CheckResult, result
from .transport import SClientOutput, classify_s_client_failure, run_s_client

ECDHE_ID = "ecdhe_groups"
FFDHE_ID = "ffdhe_groups"

ECDHE_CANDIDATES = ("x25519", "x448", "secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1")
FFDHE_CANDIDATES = ("ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192")
MINIMUM_DH_BITS = 2048
CANONICAL_GROUPS = {"prime256v1": "secp256r1", "p-256": "secp256r1", "p-384": "secp384r1", "p-521": "secp521r1"}

NEGOTIATED_13_RE = re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)")
TEMP_KEY_RE = re.compile(r"(?:Server|Peer) Temp Key:\s*(.+)")


def canonical_group(name: str) -> str:
    lowered = name.strip().lower()
    for candidate in (*ECDHE_CANDIDATES, *FFDHE_CANDIDATES):
        if candidate.lower() == lowered:
            return candidate
    return CANONICAL_GROUPS.get(lowered, lowered)


def parse_key_exchange(text: str) -> dict:
    """Extract what the handshake proved: {'group': name|None, 'family': 'ecdhe'|'dhe'|None, 'bits': int|None}."""
    outcome = {"group": None, "family": None, "bits": None}
    temp = TEMP_KEY_RE.search(text)
    if temp:
        parts = [part.strip() for part in temp.group(1).split(",")]
        bits = re.search(r"(\d+)\s*bits", temp.group(1))
        outcome["bits"] = int(bits.group(1)) if bits else None
        if parts[0].upper() == "DH":
            outcome["family"] = "dhe"
        elif parts[0].upper() == "ECDH" and len(parts) > 1:
            outcome.update(family="ecdhe", group=canonical_group(parts[1]))
        elif parts[0]:
            outcome.update(family="ecdhe", group=canonical_group(parts[0]))
    negotiated = NEGOTIATED_13_RE.search(text)
    if negotiated:
        group = canonical_group(negotiated.group(1))
        outcome.update(group=group, family="dhe" if group.startswith("ffdhe") else "ecdhe")
    return outcome


def protocol_of(text: str) -> str:
    match = re.search(r"Protocol\s*:\s*(TLSv[\d.]+)", text) or re.search(r"New, (TLSv[\d.]+),", text)
    return match.group(1) if match else ""


def _versions_to_test(context: CheckContext, wanted=("TLSv1.3", "TLSv1.2")) -> list[str]:
    if not context.observed_versions:
        return list(wanted)
    return [version for version in wanted if version in context.observed_versions]


def _version_flag(version: str) -> str:
    return {"TLSv1.3": "-tls1_3", "TLSv1.2": "-tls1_2"}[version]


def _probe(context: CheckContext, version: str, group: str | None, cipher: str | None = None) -> tuple[str, dict, SClientOutput]:
    """Returns (outcome, key_exchange, output) with outcome in accepted | refused | unreachable."""
    args = [_version_flag(version)]
    if group:
        args += ["-groups", group]
    if cipher and version != "TLSv1.3":
        args += ["-cipher", cipher]
    output = run_s_client(context, args)
    if output.connected:
        return "accepted", parse_key_exchange(output.text), output
    return classify_s_client_failure(output), {}, output


def check_ecdhe_groups(context: CheckContext) -> CheckResult:
    versions = _versions_to_test(context)
    if not versions:
        return result(ECDHE_ID, NOT_APPLICABLE, "The endpoint supports neither TLS 1.2 nor TLS 1.3, where groups are negotiated this way.")
    by_version: dict[str, dict] = {}
    default_negotiated: dict[str, str] = {}
    handshake_ok = False
    unreachable = 0
    for version in versions:
        entry = {"supported": [], "not_accepted": [], "undetermined": []}
        by_version[version] = entry
        outcome, key_exchange, _ = _probe(context, version, None, "ECDHE")
        if outcome == "accepted":
            handshake_ok = True
            if key_exchange["family"] == "ecdhe" and key_exchange["group"]:
                default_negotiated[version] = key_exchange["group"]
        for group in ECDHE_CANDIDATES:
            if not context.can_probe():
                entry["undetermined"].append(group)
                continue
            outcome, key_exchange, output = _probe(context, version, group, "ECDHE")
            if outcome == "accepted" and key_exchange["family"] == "ecdhe" and key_exchange["group"] == canonical_group(group):
                entry["supported"].append(group)
                handshake_ok = True
            elif outcome == "accepted":
                entry["undetermined"].append(group)  # connected, but the handshake did not prove this group
            elif outcome == "refused":
                entry["not_accepted"].append(group)
            else:
                entry["undetermined"].append(group)
                unreachable += 1
    proven = sorted({group for entry in by_version.values() for group in entry["supported"]})
    observations = {
        "default_negotiated": default_negotiated,
        "supported_groups": proven,
        "by_version": by_version,
        "tested_groups": list(ECDHE_CANDIDATES),
        "method": "one group offered per handshake; 'supported' is proven, 'not_accepted' means refused in that probe; the list is not a complete server inventory",
    }
    evidence = [f"{version}: {', '.join(entry['supported']) or 'none proven'}" for version, entry in by_version.items()]
    if proven:
        return result(ECDHE_ID, PASS, f"ECDHE groups accepted by the server: {', '.join(proven)}.", observations, evidence)
    if unreachable or not handshake_ok:
        return result(ECDHE_ID, INCONCLUSIVE, "No ECDHE group could be proven and some probes did not complete normally.", observations, evidence)
    return result(ECDHE_ID, FAIL, "The server completed handshakes but accepted none of the tested ECDHE groups.", observations, evidence)


def _ffdhe_proven(key_exchange: dict, group: str) -> bool:
    """Only `group` was offered, so a completed handshake with finite-field DH of that size proves it.
    (OpenSSL 3.5 prints 'Peer Temp Key: DH, 2048 bits' for TLS 1.3 and does not name the group.)"""
    if key_exchange["group"] == group:
        return True
    return key_exchange["family"] == "dhe" and key_exchange["bits"] == int(group.removeprefix("ffdhe"))


def check_ffdhe_groups(context: CheckContext) -> CheckResult:
    observations: dict = {"method": "TLS 1.2 DHE probe for the parameter size; TLS 1.3 single-group offers for the named FFDHE groups"}
    evidence: list[str] = []
    problems = 0
    dh_bits = None

    if not context.observed_versions or "TLSv1.2" in context.observed_versions:
        # SECLEVEL=0 is client-side and only lets the probe *observe* small server parameters.
        outcome, key_exchange, output = _probe(context, "TLSv1.2", None, "DHE:@SECLEVEL=0")
        if outcome == "accepted" and key_exchange["family"] == "dhe" and key_exchange["bits"]:
            dh_bits = key_exchange["bits"]
            observations["tls12_dhe"] = {"negotiated": True, "bits": dh_bits}
            evidence.append(f"TLS 1.2 DHE parameters: {dh_bits} bits")
        elif outcome == "refused":
            observations["tls12_dhe"] = {"negotiated": False, "note": "no DHE suite accepted in this probe; not a proof for other versions"}
        else:
            observations["tls12_dhe"] = {"negotiated": None, "note": "probe did not complete"}
            problems += 1
    else:
        observations["tls12_dhe"] = {"negotiated": None, "note": "TLS 1.2 not supported by the endpoint"}

    supported_named: list[str] = []
    if not context.observed_versions or "TLSv1.3" in context.observed_versions:
        for group in FFDHE_CANDIDATES:
            if not context.can_probe():
                problems += 1
                break
            outcome, key_exchange, _ = _probe(context, "TLSv1.3", group)
            if outcome == "accepted" and _ffdhe_proven(key_exchange, group):
                supported_named.append(group)
            elif outcome == "unreachable":
                problems += 1
        observations["tls13_named_groups"] = supported_named
    else:
        observations["tls13_named_groups"] = None
    observations["supported_named_groups"] = supported_named
    if supported_named:
        evidence.append(f"TLS 1.3 FFDHE: {', '.join(supported_named)}")

    if dh_bits is not None and dh_bits < MINIMUM_DH_BITS:
        return result(FFDHE_ID, FAIL, f"The server uses {dh_bits}-bit Diffie-Hellman parameters, below the {MINIMUM_DH_BITS}-bit minimum.", observations, evidence)
    if dh_bits is not None or supported_named:
        weak = "" if dh_bits is None else f" ({dh_bits}-bit parameters)"
        return result(FFDHE_ID, PASS, f"Finite-field Diffie-Hellman is offered with sufficient parameters{weak}.", observations, evidence)
    if problems:
        return result(FFDHE_ID, INCONCLUSIVE, "No DHE parameters were observed and some probes did not complete.", observations, evidence)
    return result(FFDHE_ID, NOT_APPLICABLE, "No finite-field DHE negotiation was observed (not accepted in the probes performed).", observations, evidence)
