"""Versioned contextual risk calculation, kept separate from the cryptographic grade."""
from __future__ import annotations

import csv
import html
from pathlib import Path
from typing import Any

MATRIX_VERSION = "exposure-risk-v1"
_ORDER = ("low", "medium", "high", "critical")
_ALIASES = {"moderate": "medium", "informational": "info"}


def exposure_for_endpoint(endpoint: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any] | None:
    matches = [item for item in snapshot.get("exposure_snapshot", []) if item.get("protocol") == "tls"
               and str(item.get("port")) == str(endpoint.get("port", ""))
               and item.get("target_value") in {endpoint.get("hostname", ""), endpoint.get("ip_address", "")}
               and (not item.get("sni") or item.get("sni") == endpoint.get("hostname", ""))]
    return sorted(matches, key=lambda item: (not bool(item.get("sni")), not bool(item.get("validated"))))[0] if matches else None


def assess(intrinsic_severity: str, exposure: dict[str, Any] | None) -> dict[str, Any]:
    """Adjust only confirmed, validated Internet exposure; unknown never means safe/internal."""
    source = exposure or {}
    state = source.get("state", "unknown")
    confirmed = bool(source.get("validated")) and state in {"internet_confirmed", "not_internet_confirmed"}
    base = _ALIASES.get(str(intrinsic_severity).lower(), str(intrinsic_severity).lower())
    if not confirmed or base not in _ORDER:
        return {"matrix_version": MATRIX_VERSION, "assessed": False, "contextual_severity": None,
                "intrinsic_severity": intrinsic_severity, "exposure_state": "unknown" if not confirmed else state,
                "reason": "exposure is unknown or not validated; contextual weighting was not evaluated"}
    index = _ORDER.index(base)
    delta = 1 if state == "internet_confirmed" else -1
    adjusted = _ORDER[max(0, min(len(_ORDER) - 1, index + delta))]
    direction = "increased" if delta > 0 else "reduced"
    return {"matrix_version": MATRIX_VERSION, "assessed": True, "contextual_severity": adjusted,
            "intrinsic_severity": intrinsic_severity, "exposure_state": state,
            "reason": f"confirmed exposure {direction} one severity level", "source": source.get("source", ""),
            "evidence_method": source.get("evidence_method", ""), "justification": source.get("justification", ""),
            "confidence": source.get("confidence", "unknown"), "observed_at": source.get("observed_at"),
            "validated_at": source.get("validated_at")}


def report_rows(report_model: dict[str, Any], snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    endpoints = {item.get("endpoint_id"): item for item in report_model.get("endpoints", [])}
    rows = []
    for finding in report_model.get("findings", []):
        for endpoint_id in finding.get("affected_endpoint_ids", []):
            endpoint = endpoints.get(endpoint_id)
            if endpoint is None:
                continue
            exposure = exposure_for_endpoint(endpoint, snapshot)
            risk = assess(finding.get("severity", ""), exposure)
            rows.append({"endpoint_id": endpoint_id, "endpoint": f"{endpoint.get('hostname') or endpoint.get('ip_address')}:{endpoint.get('port')}",
                         "finding_id": finding.get("finding_id", ""), "finding": finding.get("title", ""),
                         "intrinsic_severity": finding.get("severity", ""),
                         "contextual_severity": risk.get("contextual_severity") or "not_evaluated",
                         "exposure": risk.get("exposure_state", "unknown"), "source": risk.get("source", ""),
                         "method": risk.get("evidence_method", ""), "justification": risk.get("justification", ""),
                         "confidence": risk.get("confidence", "unknown"), "matrix_version": MATRIX_VERSION,
                         "assessed": risk.get("assessed", False)})
    return rows


def append_html(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    content = path.read_text(encoding="utf-8")
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(row[key]))}</td>" for key in
                ("endpoint", "finding", "intrinsic_severity", "contextual_severity", "exposure", "source", "method", "justification", "confidence")) + "</tr>" for row in rows)
    section = ('<section aria-label="Contextual exposure risk"><h2>Contextual exposure risk</h2>'
               '<p>Cryptographic grade and intrinsic severity are unchanged. Unknown or unvalidated exposure is not weighted.</p>'
               '<table><thead><tr><th>Endpoint</th><th>Finding</th><th>Intrinsic severity</th><th>Contextual severity</th><th>Exposure</th><th>Source</th><th>Method</th><th>Justification</th><th>Confidence</th></tr></thead>'
               f'<tbody>{body}</tbody></table><p>Matrix: {MATRIX_VERSION}</p></section>')
    marker = "</body>"
    content = content.replace(marker, section + marker, 1) if marker in content else content + section
    path.write_text(content, encoding="utf-8")


def append_markdown(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with path.open("a", encoding="utf-8") as stream:
        stream.write("\n## Contextual exposure risk\n\nCryptographic grades and intrinsic severity remain unchanged. Unknown or unvalidated exposure is not weighted.\n\n")
        stream.write("| Endpoint | Finding | Intrinsic severity | Contextual severity | Exposure | Source | Method | Justification | Confidence |\n|---|---|---|---|---|---|---|---|---|\n")
        for row in rows:
            cells = [row[k] for k in ("endpoint", "finding", "intrinsic_severity", "contextual_severity", "exposure", "source", "method", "justification", "confidence")]
            stream.write("| " + " | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in cells) + " |\n")
        stream.write(f"\nMatrix: `{MATRIX_VERSION}`.\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("endpoint", "finding_id", "finding", "intrinsic_severity", "contextual_severity",
                                                    "exposure", "source", "method", "justification", "confidence", "matrix_version", "assessed"))
        writer.writeheader()
        writer.writerows({key: row[key] for key in writer.fieldnames} for row in rows)

