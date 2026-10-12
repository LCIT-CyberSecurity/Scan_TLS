"""
A1 - FQDN / SAN identity validation (RFC 9525 rules).

The reference identity is the name the user actually asked to scan (or the IP address when the
target was an address): never a reverse-DNS (PTR) name. This is a host-name check only; whether the
chain is trusted is a separate PKI control.
"""

from __future__ import annotations

import ipaddress
import socket

from cryptography import x509
from cryptography.x509.oid import NameOID

from ..pki import collect_peer_certificate_chain
from .contracts import FAIL, INCONCLUSIVE, NOT_TESTED, PASS, CheckContext, CheckResult, result

CHECK_ID = "hostname_san"
MAX_REFERENCES = 5
MAX_LISTED_NAMES = 20


def to_a_label(name: str) -> str:
    """Lower-case ASCII (A-label) form of a DNS name, without the trailing dot. Raises ValueError."""
    cleaned = name.strip().rstrip(".")
    if not cleaned:
        raise ValueError("empty name")
    try:
        cleaned.encode("ascii")
        return cleaned.lower()
    except UnicodeEncodeError:
        pass
    try:
        return cleaned.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError(f"invalid internationalised name: {error}") from error


def dns_name_matches(pattern: str, reference: str) -> bool:
    """Match a certificate DNS name (possibly `*.example.org`) against a reference DNS name."""
    try:
        pattern, reference = to_a_label(pattern), to_a_label(reference)
    except ValueError:
        return False
    if "*" not in pattern:
        return pattern == reference
    labels = pattern.split(".")
    # only the whole left-most label may be a wildcard, with at least two labels after it (no `*.com`)
    if labels[0] != "*" or len(labels) < 3 or any("*" in label for label in labels[1:]):
        return False
    ref_labels = reference.split(".")
    return len(ref_labels) == len(labels) and ref_labels[1:] == labels[1:] and bool(ref_labels[0])


def reference_kind(reference: str) -> str:
    try:
        ipaddress.ip_address(reference)
        return "ip"
    except ValueError:
        return "dns"


def certificate_identities(certificate: x509.Certificate) -> dict:
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_present = True
        dns_names = list(san.get_values_for_type(x509.DNSName))
        ip_addresses = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        san_present, dns_names, ip_addresses = False, [], []
    common_names = [attribute.value for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return {"san_present": san_present, "dns": dns_names, "ip": ip_addresses, "cn": [str(value) for value in common_names]}


def match_identity(reference: str, identities: dict) -> dict:
    """Pure matching logic. SAN is authoritative: the CN is never used for matching."""
    kind = reference_kind(reference)
    outcome = {"reference": reference, "reference_kind": kind, "matched": False, "matched_by": "none", "matched_entry": "", "wildcard": False}
    if kind == "ip":
        wanted = ipaddress.ip_address(reference)
        for entry in identities["ip"]:
            if ipaddress.ip_address(entry) == wanted:
                outcome.update(matched=True, matched_by="san_ip", matched_entry=entry)
                return outcome
    else:
        for entry in identities["dns"]:
            if dns_name_matches(entry, reference):
                outcome.update(matched=True, matched_by="san_dns", matched_entry=entry, wildcard="*" in entry)
                return outcome
    if not identities["san_present"] and identities["cn"]:
        outcome["cn_only"] = True  # legacy certificate without SAN: not accepted by current clients
    return outcome


def reference_identities(context: CheckContext) -> tuple[str, ...]:
    """The names requested by the user, or the scanned address when the target was an address."""
    if context.reference_names:
        return tuple(dict.fromkeys(context.reference_names))[:MAX_REFERENCES]
    return (context.host,) if context.host else ()


def check_hostname_san(context: CheckContext) -> CheckResult:
    references = reference_identities(context)
    if not references:
        return result(CHECK_ID, NOT_TESTED, "no reference identity: no name was requested and the endpoint has no address")
    findings, evidence, errors = [], [], 0
    identities_seen: dict = {}
    for reference in references:
        if not context.can_probe():
            errors += 1
            findings.append({"reference": reference, "status": INCONCLUSIVE, "error": "time budget exhausted or scan cancelled"})
            continue
        sni = "" if reference_kind(reference) == "ip" else reference
        extra = {"starttls_protocol": context.starttls} if context.starttls_protocol is not None else {}
        chain = collect_peer_certificate_chain(context.host, context.port, sni, int(context.probe_timeout()), **extra)
        if not chain.certificates:
            errors += 1
            findings.append({"reference": reference, "status": INCONCLUSIVE, "error": chain.error or "no certificate presented"})
            continue
        identities = certificate_identities(chain.certificates[0])
        identities_seen = identities
        outcome = match_identity(reference, identities)
        outcome["status"] = PASS if outcome["matched"] else FAIL
        findings.append(outcome)
        evidence.append(f"{reference}: {'matches ' + outcome['matched_entry'] if outcome['matched'] else 'no matching SAN entry'}")
    statuses = {item["status"] for item in findings}
    if FAIL in statuses:
        status = FAIL
    elif statuses == {PASS}:
        status = PASS
    else:
        status = INCONCLUSIVE
    observations = {
        "references": findings,
        "san_dns": identities_seen.get("dns", [])[:MAX_LISTED_NAMES],
        "san_ip": identities_seen.get("ip", [])[:MAX_LISTED_NAMES],
        "san_present": identities_seen.get("san_present"),
        "common_names": identities_seen.get("cn", [])[:3],
    }
    if status == PASS:
        message = "The certificate identity matches every requested name."
    elif status == FAIL:
        bad = ", ".join(item["reference"] for item in findings if item["status"] == FAIL)
        message = f"The certificate does not cover the requested identity: {bad}. This is independent of chain trust."
    else:
        message = "The certificate could not be retrieved for every requested name; the identity is not established."
    return result(CHECK_ID, status, message, observations, evidence)


def resolve_requested_names(targets: str) -> dict[str, tuple[str, ...]]:
    """Map each address to the DNS names the user asked for (IP/CIDR targets contribute nothing)."""
    names: dict[str, list[str]] = {}
    for target in targets.split():
        try:
            ipaddress.ip_network(target, strict=False)
            continue
        except ValueError:
            pass
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)}
        except (socket.gaierror, OSError):
            continue
        for address in addresses:
            if target not in names.setdefault(address, []):
                names[address].append(target.rstrip("."))
    return {address: tuple(values) for address, values in names.items()}
