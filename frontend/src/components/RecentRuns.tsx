import { ChevronDown, ChevronRight } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { Run } from "../api/types";
import { useI18n } from "../i18n";
import { formatDate, formatDuration } from "../lib/utils";
import { StatusBadge } from "./common";
import { Badge } from "./ui/badge";

/** Dashboard list: one row per scan (latest run first), a chevron unfolds its previous runs. */
export function RecentRuns({ runs }: { runs: Run[] }) {
  const { t, locale } = useI18n();
  const [open, setOpen] = useState<Set<string>>(new Set());
  const groups = useMemo(() => {
    const map = new Map<string, Run[]>();
    for (const r of [...runs].sort((a, b) => b.queued_at.localeCompare(a.queued_at))) {
      const key = r.definition_id ?? `name:${r.name}`;
      map.set(key, [...(map.get(key) ?? []), r]);
    }
    return [...map.entries()];
  }, [runs]);
  const toggle = (key: string) => setOpen((s) => { const n = new Set(s); if (n.has(key)) n.delete(key); else n.add(key); return n; });
  return (
    <div className="table-scroll">
      <table className="simple-table">
        <thead><tr><th style={{ width: 36 }} /><th>{t("col.name")}</th><th>{t("col.status")}</th><th>{t("col.date")}</th><th>{t("col.duration")}</th><th>{t("col.nonCompliant")}</th></tr></thead>
        <tbody>
          {groups.map(([key, list]) => {
            const last = list[0];
            const expanded = open.has(key);
            return (
              <Fragment key={key}>
                <tr className="group-row">
                  <td>{list.length > 1 && <button type="button" className="button button--ghost button--icon" aria-expanded={expanded} aria-label={t("scans.history")} onClick={() => toggle(key)}>{expanded ? <ChevronDown /> : <ChevronRight />}</button>}</td>
                  <td><Link className="row-link" to={`/scans/${last.id}`}>{last.name}</Link> {list.length > 1 && <Badge tone="primary">{t("scans.runsCount", { n: list.length })}</Badge>}</td>
                  <td><StatusBadge status={last.status} /></td>
                  <td>{formatDate(last.queued_at, locale)}</td>
                  <td>{formatDuration(last.duration_seconds)}</td>
                  <td>{last.summary?.non_compliant_endpoints ?? "—"}</td>
                </tr>
                {expanded && list.map((r) => (
                  <tr key={r.id} className="history-row">
                    <td />
                    <td><Link className="row-link" to={`/scans/${r.id}`}>{formatDate(r.queued_at, locale)}</Link></td>
                    <td><StatusBadge status={r.status} /></td>
                    <td />
                    <td className="text-muted">{formatDuration(r.duration_seconds)}</td>
                    <td>{r.summary?.non_compliant_endpoints ?? "—"}</td>
                  </tr>
                ))}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
