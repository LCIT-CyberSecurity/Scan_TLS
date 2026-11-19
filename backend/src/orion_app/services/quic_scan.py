"""Bounded QUIC / HTTP/3 observations using aioquic (UDP only, no application requests)."""
from __future__ import annotations

import asyncio
import csv
import html
import io
import ipaddress
import logging
import ssl
import time
from pathlib import Path
from typing import Any

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.client import connect
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.configuration import QuicConfiguration

logger = logging.getLogger("orion_app.quic")
SOURCE = "aioquic QUIC handshake"
DEFAULTS = {"enabled": False, "ports": [443], "timeout_seconds": 3, "retries": 0,
            "max_targets": 32, "max_parallelism": 4, "max_duration_seconds": 30}
LIMITS = {"timeout_seconds": (1, 10), "retries": (0, 1), "max_targets": (1, 64),
          "max_parallelism": (1, 8), "max_duration_seconds": (1, 120)}


def validate_profile(value: Any) -> None:
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ValueError("scan.quic contains unsupported fields")
    if "enabled" in value and not isinstance(value["enabled"], bool):
        raise ValueError("scan.quic.enabled must be a boolean")
    ports = value.get("ports", DEFAULTS["ports"])
    if (not isinstance(ports, list) or not 1 <= len(ports) <= 16
            or any(isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535 for p in ports)
            or len(set(ports)) != len(ports)):
        raise ValueError("scan.quic.ports must contain 1–16 unique UDP ports")
    for key, (minimum, maximum) in LIMITS.items():
        item = value.get(key, DEFAULTS[key])
        if isinstance(item, bool) or not isinstance(item, int) or not minimum <= item <= maximum:
            raise ValueError(f"scan.quic.{key} must be between {minimum} and {maximum}")


def effective_config(profile: dict[str, Any] | None, override: bool | None) -> dict[str, Any] | None:
    settings = {**DEFAULTS, **(profile or {})}
    validate_profile(settings)
    settings["enabled"] = bool(settings["enabled"] if override is None else override)
    return settings if settings["enabled"] else None


def _version_name(value: Any) -> str | None:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return None
    return {0x00000001: "QUICv1", 0x6B3343CF: "QUICv2"}.get(numeric, f"0x{numeric:08x}")


def _cipher_name(protocol: QuicConnectionProtocol) -> str | None:
    tls = getattr(getattr(protocol, "_quic", None), "tls", None)
    key_schedule = getattr(tls, "key_schedule", None)
    value = (getattr(tls, "_cipher_suite", None) or getattr(tls, "cipher_suite", None)
             or getattr(key_schedule, "cipher_suite", None))
    if value is None:
        return None
    name = getattr(value, "name", None)
    if name:
        return str(name)
    try:
        from aioquic.tls import CipherSuite
        return CipherSuite(value).name
    except (ImportError, ValueError, TypeError):
        return str(value)


def _certificate(protocol: QuicConnectionProtocol) -> dict[str, Any] | None:
    tls = getattr(getattr(protocol, "_quic", None), "tls", None)
    cert = getattr(tls, "_peer_certificate", None)
    if cert is None:
        chain = getattr(tls, "_peer_certificate_chain", None)
        cert = chain[0] if chain else None
    if cert is None:
        return None
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        der = cert.public_bytes(serialization.Encoding.DER)
        return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                "serial_number": format(cert.serial_number, "x"),
                "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex()}
    except (AttributeError, TypeError, ValueError):
        return None


def _cipher_family(cipher: str | None) -> str | None:
    if not cipher:
        return None
    name = cipher.upper()
    if "CHACHA20" in name:
        return "CHACHA20-POLY1305"
    if "AES_128_GCM" in name or "AES_256_GCM" in name:
        return "AES-GCM"
    if "AES_128_CCM" in name or "AES_256_CCM" in name:
        return "AES-CCM"
    return None


def evaluate_tls_policy_subset(observation: dict[str, Any], policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evaluate only QUIC-applicable TLS 1.3 version/cipher requirements; never grade the full policy."""
    results = []
    for policy in policies:
        content = policy.get("content") or {}
        checks = []
        if observation.get("status") != "observed":
            version_state = cipher_state = "inconclusive"
        else:
            version_state = "compliant" if "TLSv1.3" in (content.get("allowed_versions") or []) else "non_compliant"
            family = _cipher_family(observation.get("cipher_suite"))
            allowed = content.get("allowed_cipher_algorithms") or []
            cipher_state = ("not_evaluated" if family is None else
                            "compliant" if family in allowed else "non_compliant")
        checks.extend([
            {"control": "tls_version", "status": version_state, "observed": "TLSv1.3" if observation.get("status") == "observed" else None},
            {"control": "cipher_suite", "status": cipher_state, "observed": observation.get("cipher_suite")},
            {"control": "certificate_trust_expiry_revocation", "status": "not_evaluated",
             "reason": "QUIC probe records certificate metadata but does not validate its chain, hostname, expiry or revocation."},
        ])
        results.append({"policy": policy.get("name", ""), "status": "not_evaluated", "checks": checks,
                        "note": "Only explicitly listed QUIC-applicable TLS 1.3 checks are evaluated; this is not a full policy verdict."})
    return results


def _target_ports(passes: list[dict[str, Any]], ports: list[int], max_targets: int) -> tuple[list[str], int]:
    targets = sorted({target for item in passes for target in item.get("targets", [])})
    return targets[:max_targets], max(0, len(targets) - max_targets)


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


class _ProbeProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.observation: dict[str, Any] | None = None

    def quic_event_received(self, event) -> None:
        super().quic_event_received(event)
        if isinstance(event, HandshakeCompleted):
            quic = getattr(self, "_quic", None)
            self.observation = {
                "status": "observed", "tls_version": "TLSv1.3", "alpn": event.alpn_protocol,
                "http3_status": "negotiated" if event.alpn_protocol == "h3" else "not_negotiated",
                "quic_version": _version_name(getattr(quic, "_version", None)),
                "cipher_suite": _cipher_name(self), "certificate": _certificate(self),
            }


async def _probe(target: str, port: int, timeout: int) -> dict[str, Any]:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"], idle_timeout=float(timeout),
                                       server_name=None if _is_ip(target) else target,
                                       verify_mode=ssl.CERT_NONE)
    try:
        async with asyncio.timeout(timeout):
            async with connect(target, port, configuration=configuration, create_protocol=_ProbeProtocol,
                               wait_connected=True) as protocol:
                return protocol.observation or {"status": "inconclusive", "reason": "QUIC connection completed without a TLS handshake event."}
    except TimeoutError:
        return {"status": "inconclusive", "reason": "No QUIC handshake response before the configured timeout."}
    except asyncio.CancelledError:
        raise
    except Exception as error:  # network and protocol failures are observations, not scan failures
        logger.debug("QUIC probe inconclusive target=%s port=%s error=%s", target, port, type(error).__name__)
        return {"status": "inconclusive", "reason": f"QUIC handshake was inconclusive ({type(error).__name__})."}


async def _scan(config: dict[str, Any], passes: list[dict[str, Any]], policies: list[dict[str, Any]], cancel=None):
    targets, skipped = _target_ports(passes, config["ports"], config["max_targets"])
    semaphore = asyncio.Semaphore(config["max_parallelism"])
    deadline = time.monotonic() + config["max_duration_seconds"]
    async def one(target: str, port: int):
        async with semaphore:
            if cancel is not None and cancel.is_set():
                result = {"status": "not_tested", "reason": "Scan cancelled before QUIC probe."}
            else:
                result = {"status": "inconclusive", "reason": "QUIC time budget reached."}
                for attempt in range(config["retries"] + 1):
                    remaining = int(deadline - time.monotonic())
                    if remaining <= 0 or (cancel is not None and cancel.is_set()):
                        break
                    result = await _probe(target, port, min(config["timeout_seconds"], remaining))
                    if result.get("status") == "observed":
                        break
            row = {"target": target, "transport": "udp", "port": port, "source": SOURCE, **result}
            row["policy_evaluations"] = evaluate_tls_policy_subset(row, policies)
            return row
    pairs = [(target, port) for target in targets for port in config["ports"]]
    tasks = [asyncio.create_task(one(target, port)) for target, port in pairs]
    observations = []
    try:
        async with asyncio.timeout(config["max_duration_seconds"]):
            observations = await asyncio.gather(*tasks)
    except TimeoutError:
        for task in tasks:
            if not task.done():
                task.cancel()
        values = await asyncio.gather(*tasks, return_exceptions=True)
        observations = [value if isinstance(value, dict) else {
            "target": target, "transport": "udp", "port": port, "status": "not_tested",
            "reason": "Global QUIC time budget expired before this probe completed.",
            "source": SOURCE, "policy_evaluations": [],
        } for (target, port), value in zip(pairs, values)]
    if skipped:
        observations.append({"target": "", "transport": "udp", "port": None, "status": "not_tested",
                             "reason": f"{skipped} target(s) exceeded the profile QUIC target limit.",
                             "source": SOURCE, "policy_evaluations": []})
    observations.sort(key=lambda row: (row["target"], row["port"] or 0))
    return observations


def scan(config: dict[str, Any] | None, passes: list[dict[str, Any]], policies: list[dict[str, Any]], cancel=None):
    if not config or not config.get("enabled"):
        return []
    validate_profile({key: value for key, value in config.items() if key != "enabled"} | {"enabled": True})
    if cancel is not None and cancel.is_set():
        return []
    return asyncio.run(_scan(config, passes, policies, cancel))


def write_csv(observations: list[dict[str, Any]], export_dir: Path, run_id: str, formats: list[str]) -> list[str]:
    if not observations or "csv" not in formats:
        return []
    path = export_dir / run_id / "quic-results.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ("target", "transport", "port", "status", "tls_version", "quic_version", "alpn", "http3_status",
              "cipher_suite", "reason", "policy_evaluations", "source")
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in observations:
        writer.writerow({**row, "policy_evaluations": str(row.get("policy_evaluations") or [])})
    path.write_text(stream.getvalue(), encoding="utf-8")
    return [str(path)]


def render_html(observations: list[dict[str, Any]]) -> str:
    rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(row.get(key) or '—'))}</td>"
                   for key in ("target", "transport", "port", "status", "quic_version", "tls_version", "alpn", "cipher_suite", "reason")) + "</tr>"
                   for row in observations)
    return ("<section class=\"panel report-chapter\" id=\"quic\"><h2>QUIC / HTTP/3 observations</h2>"
            "<p>UDP-only, bounded aioquic handshakes. A timeout or silence is inconclusive and does not prove that QUIC is absent. "
            "TLS certificate trust, hostname, expiry and revocation are not evaluated by this probe.</p>"
            "<table><thead><tr><th>Target</th><th>Transport</th><th>Port</th><th>Status</th><th>QUIC</th><th>TLS</th><th>ALPN</th><th>Cipher suite</th><th>Observation</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>")
