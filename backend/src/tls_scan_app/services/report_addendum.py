"""Extra sections of the WebUI reports, computed from persisted results and appended *after* the engine generated the report
(the engine, and therefore the Standalone reports, are untouched).

Sections: evolution since the previous comparable scan, certificates to renew, trend of the last scans, scan scope (exclusions,
skipped hosts). Each one is omitted when there is nothing to say; nothing here re-evaluates a result.
"""
from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import RunEndpoint, ScanRun
from tls_scan_app.services import comparison, evolution

EXPIRY_DAYS = 90
TREND_RUNS = 6
MAX_ROWS = 15
WARNINGS = {
    "scope_differs": "the targets differ between the two scans",
    "profile_differs": "the scan profile differs between the two scans",
    "policy_versions_differ": "the policy versions differ between the two scans",
    "incomplete_runs": "one of the two scans is incomplete (skipped hosts)",
}


def _day(value: datetime | None) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if value else "-"


def _certificates(db: DbSession, run: ScanRun) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for e in db.execute(select(RunEndpoint).where(RunEndpoint.run_id == run.id)).scalars():
        cert = e.certificate or {}
        days = cert.get("remaining_days")
        if not isinstance(days, int | float) or isinstance(days, bool) or days > EXPIRY_DAYS:
            continue
        key = cert.get("fingerprint") or f"{e.endpoint_id}"
        item = seen.setdefault(key, {"subject": cert.get("subject") or e.hostname or e.ip_address, "valid_until": cert.get("valid_until"),
                                     "remaining_days": int(days), "endpoints": []})
        item["endpoints"].append(f"{e.hostname or e.ip_address}:{e.port}")
    return sorted(seen.values(), key=lambda c: c["remaining_days"])


def build(db: DbSession, run: ScanRun) -> dict[str, Any]:
    """The run's rows must already be flushed."""
    previous = comparison.previous_comparable(db, run) if run.definition_id else None
    out: dict[str, Any] = {"evolution": None, "certificates": _certificates(db, run), "trend": [], "scope": None}
    if previous is not None:
        out["evolution"] = {"previous": {"id": str(previous.id), "name": previous.name, "finished_at": previous.finished_at},
                            **evolution.summarize_comparison(db, previous, run)}
    if run.definition_id:
        earlier = db.execute(select(ScanRun).where(ScanRun.definition_id == run.definition_id, ScanRun.id != run.id,
                                                   ScanRun.status.in_(("completed", "partial")), ScanRun.finished_at.is_not(None))
                             .order_by(ScanRun.finished_at.desc()).limit(TREND_RUNS - 1)).scalars().all()
        runs = [*reversed(earlier), run]
        counts = evolution.severity_counts(db, [r.id for r in runs])
        out["trend"] = [{"finished_at": r.finished_at or datetime.now(UTC), "endpoints": (r.summary or {}).get("total_endpoints", 0),
                         **{lv: counts[r.id][lv]["occurrences"] for lv in evolution.LEVELS}} for r in runs] if len(runs) > 1 else []
    excl = (run.config_snapshot or {}).get("exclusions") or {}
    skipped = list(run.skipped_hosts or [])
    if excl.get("entries") or skipped:
        out["scope"] = {"entries": excl.get("entries", []), "removed_targets": excl.get("removed_targets", []),
                        "partial_targets": excl.get("partial_targets", []), "skipped_hosts": skipped[:MAX_ROWS], "skipped_total": len(skipped)}
    return out


def has_content(addendum: dict[str, Any]) -> bool:
    return bool(addendum["evolution"] or addendum["certificates"] or addendum["trend"] or addendum["scope"])


# ---------- HTML ----------
def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _table(header: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in header)
    body = "".join("<tr>" + "".join(f"<td>{_e(c)}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _section(title: str, eyebrow: str, inner: str, ident: str) -> str:
    return (f'    <section class="panel report-chapter" id="{ident}"><div class="section-heading"><div><p class="eyebrow">{_e(eyebrow)}</p>'
            f"<h2>{_e(title)}</h2></div></div>{inner}</section>\n")


def render_html(addendum: dict[str, Any]) -> str:
    parts: list[str] = []
    ev = addendum["evolution"]
    if ev:
        c = ev["counts"]
        inner = (f'<p>Compared with the scan of <strong>{_e(_day(ev["previous"]["finished_at"]))}</strong>: <strong>{c["new"]}</strong> new, '
                 f'<strong>{c["fixed"]}</strong> fixed, <strong>{c["persistent"]}</strong> persistent, <strong>{c["not_retested"]}</strong> not retested '
                 f'(a service not tested again is never reported as fixed). Endpoints: +{ev["endpoints_added"]} / -{ev["endpoints_removed"]}; '
                 f'compliance: {ev["compliance"]["improved"]} improved, {ev["compliance"]["degraded"]} degraded.</p>')
        for warning in ev["warnings"]:
            inner += f'<p><em>Caution: {_e(WARNINGS.get(warning, warning))}.</em></p>'
        for label, key in (("New findings", "new"), ("Fixed findings", "fixed")):
            if ev[key]:
                inner += f"<h3>{label}</h3>" + _table(["Severity", "Finding", "Endpoints"], [[i["severity"], i["title"] or i["finding_id"], i["endpoints"]] for i in ev[key]])
        if ev["certificate_changes"]:
            inner += "<h3>Certificate changes</h3>" + _table(["Endpoint", "Before", "After", "Valid until"],
                                                            [[i["endpoint_id"], i["before"], i["after"], i["valid_until_after"]] for i in ev["certificate_changes"]])
        parts.append(_section("Evolution since the previous scan", "Evolution", inner, "evolution"))
    if addendum["certificates"]:
        rows = [[c["subject"], c["valid_until"], c["remaining_days"], ", ".join(c["endpoints"][:3]) + (" …" if len(c["endpoints"]) > 3 else "")] for c in addendum["certificates"][:MAX_ROWS]]
        parts.append(_section(f"Certificates to renew (within {EXPIRY_DAYS} days)", "Certificates",
                              "<p>Negative values are already expired.</p>" + _table(["Subject", "Valid until", "Days remaining", "Endpoints"], rows), "renewals"))
    if addendum["trend"]:
        rows = [[_day(t["finished_at"]), t["endpoints"], t["critical"], t["high"], t["medium"], t["low"]] for t in addendum["trend"]]
        parts.append(_section(f"Trend over the last {len(addendum['trend'])} scans", "Trend",
                              "<p>Occurrences (finding × endpoint) per severity.</p>" + _table(["Scan", "Endpoints", "Critical", "High", "Medium", "Low"], rows), "trend"))
    sc = addendum["scope"]
    if sc:
        inner = ""
        if sc["entries"]:
            inner += "<p>Exclusions applied to this scan:</p>" + _table(["Entry", "Defined at"], [[e["value"], e["scope"]] for e in sc["entries"]])
            if sc["removed_targets"]:
                inner += f'<p>Targets removed before the scan: {_e(", ".join(sc["removed_targets"][:MAX_ROWS]))}</p>'
        if sc["skipped_total"]:
            inner += f'<p>Hosts skipped ({sc["skipped_total"]}): {_e(", ".join(map(str, sc["skipped_hosts"])))}{" …" if sc["skipped_total"] > len(sc["skipped_hosts"]) else ""}</p>'
        parts.append(_section("Scan scope", "Scope", inner, "scope"))
    return "".join(parts)


def apply_to_html(path: Path, addendum: dict[str, Any]) -> bool:
    if not path.is_file() or not has_content(addendum):
        return False
    text = path.read_text(encoding="utf-8")
    marker = '    <footer class="report-footer"'
    section = render_html(addendum)
    if marker not in text or not section:
        return False
    path.write_text(text.replace(marker, section + marker, 1), encoding="utf-8")
    return True


# ---------- Markdown ----------
def _md_table(header: list[str], rows: list[list[Any]]) -> list[str]:
    def cell(value: Any) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ")
    return ["| " + " | ".join(header) + " |", "|" + "---|" * len(header), *("| " + " | ".join(cell(c) for c in row) + " |" for row in rows), ""]


def render_markdown(addendum: dict[str, Any]) -> str:
    lines: list[str] = []
    ev = addendum["evolution"]
    if ev:
        c = ev["counts"]
        lines += ["", "## Evolution since the previous scan", "",
                  f"Compared with the scan of **{_day(ev['previous']['finished_at'])}**: **{c['new']}** new, **{c['fixed']}** fixed, **{c['persistent']}** persistent, "
                  f"**{c['not_retested']}** not retested (a service not tested again is never reported as fixed). Endpoints: +{ev['endpoints_added']} / -{ev['endpoints_removed']}; "
                  f"compliance: {ev['compliance']['improved']} improved, {ev['compliance']['degraded']} degraded.", ""]
        lines += [f"> Caution: {WARNINGS.get(w, w)}." for w in ev["warnings"]]
        for label, key in (("New findings", "new"), ("Fixed findings", "fixed")):
            if ev[key]:
                lines += ["", f"### {label}", "", *_md_table(["Severity", "Finding", "Endpoints"], [[i["severity"], i["title"] or i["finding_id"], i["endpoints"]] for i in ev[key]])]
        if ev["certificate_changes"]:
            lines += ["", "### Certificate changes", "", *_md_table(["Endpoint", "Before", "After", "Valid until"], [[i["endpoint_id"], i["before"], i["after"], i["valid_until_after"]] for i in ev["certificate_changes"]])]
    if addendum["certificates"]:
        rows = [[c["subject"], c["valid_until"], c["remaining_days"], ", ".join(c["endpoints"][:3])] for c in addendum["certificates"][:MAX_ROWS]]
        lines += ["", f"## Certificates to renew (within {EXPIRY_DAYS} days)", "", "Negative values are already expired.", "", *_md_table(["Subject", "Valid until", "Days remaining", "Endpoints"], rows)]
    if addendum["trend"]:
        rows = [[_day(t["finished_at"]), t["endpoints"], t["critical"], t["high"], t["medium"], t["low"]] for t in addendum["trend"]]
        lines += ["", f"## Trend over the last {len(addendum['trend'])} scans", "", "Occurrences (finding × endpoint) per severity.", "", *_md_table(["Scan", "Endpoints", "Critical", "High", "Medium", "Low"], rows)]
    sc = addendum["scope"]
    if sc:
        lines += ["", "## Scan scope", ""]
        if sc["entries"]:
            lines += ["Exclusions applied to this scan:", "", *_md_table(["Entry", "Defined at"], [[e["value"], e["scope"]] for e in sc["entries"]])]
            if sc["removed_targets"]:
                lines += [f"Targets removed before the scan: {', '.join(sc['removed_targets'][:MAX_ROWS])}", ""]
        if sc["skipped_total"]:
            lines += [f"Hosts skipped ({sc['skipped_total']}): {', '.join(map(str, sc['skipped_hosts']))}", ""]
    return "\n".join(lines) + "\n" if lines else ""


def apply_to_markdown(path: Path, addendum: dict[str, Any]) -> bool:
    if not path.is_file() or not has_content(addendum):
        return False
    section = render_markdown(addendum)
    if not section:
        return False
    text = path.read_text(encoding="utf-8")
    path.write_text(text.rstrip("\n") + "\n" + section, encoding="utf-8")
    return True
