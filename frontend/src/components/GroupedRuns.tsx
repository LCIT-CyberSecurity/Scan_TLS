import { ChevronDown, ChevronRight, FileText, RotateCcw, Trash2, TrendingDown, TrendingUp } from "lucide-react";
import { Fragment, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { downloadUrl } from "../api/client";
import type { Run } from "../api/types";
import { useI18n } from "../i18n";
import { formatDate, formatDuration } from "../lib/utils";
import { ConfirmButton, Empty, StatusBadge } from "./common";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

interface Group { key: string; name: string; definitionId: string | null; runs: Run[] }
const nc = (r?: Run) => r?.summary?.non_compliant_endpoints;
const active = (r: Run) => r.status === "queued" || r.status === "running";

/** One row per scan (definition) with its latest result and trend; its history unfolds underneath. */
export function GroupedRuns({ runs, canDelete, canCancel, onRescan, onDelete, onCancel }: {
  runs: Run[]; canDelete: boolean; canCancel: (r: Run) => boolean;
  onRescan: (definitionId: string) => void; onDelete: (runId: string) => void; onCancel: (runId: string) => void;
}) {
  const { t, locale } = useI18n();
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [q, setQ] = useState("");
  const groups = useMemo<Group[]>(() => {
    const map = new Map<string, Group>();
    for (const r of runs) { // runs arrive newest first
      const key = r.definition_id ?? `name:${r.name}`;
      const g = map.get(key) ?? { key, name: r.name, definitionId: r.definition_id, runs: [] };
      g.runs.push(r); map.set(key, g);
    }
    return [...map.values()].filter((g) => g.name.toLowerCase().includes(q.toLowerCase()));
  }, [runs, q]);
  const toggle = (key: string) => setOpen((s) => { const n = new Set(s); if (n.has(key)) n.delete(key); else n.add(key); return n; });

  const reportButton = (r: Run) => r.reports.some((x) => x.format === "html") && <Button asChild size="sm" variant="outline"><a href={downloadUrl(r.id, "html", true)} target="_blank" rel="noreferrer"><FileText />{t("action.report")}</a></Button>;
  const runActions = (r: Run): ReactNode => (
    <div className="row-actions">
      {reportButton(r)}
      {canDelete && !active(r) && <ConfirmButton variant="outline" label={<Trash2 className="size-4" />} confirm={t("confirm.deleteScan")} onConfirm={() => onDelete(r.id)} />}
      {active(r) && canCancel(r) && <ConfirmButton variant="outline" label={t("action.cancelScan")} confirm={t("confirm.cancelScan")} onConfirm={() => onCancel(r.id)} />}
    </div>
  );

  return (
    <div>
      <div className="filter-bar"><input type="search" className="compact" style={{ width: 260 }} placeholder={t("scans.search")} aria-label={t("scans.search")} value={q} onChange={(e) => setQ(e.target.value)} /></div>
      {!groups.length ? <Empty>{t("scans.none")}</Empty> : (
        <div className="table-scroll">
          <table className="simple-table">
            <thead><tr><th style={{ width: 36 }} /><th>{t("col.name")}</th><th>{t("col.status")}</th><th>{t("scans.last")}</th><th>{t("col.nonCompliant")}</th><th /></tr></thead>
            <tbody>
              {groups.map((g) => {
                const last = g.runs[0];
                const done = g.runs.filter((r) => nc(r) != null);
                const delta = done.length > 1 ? (nc(done[0]) as number) - (nc(done[1]) as number) : null;
                const expanded = open.has(g.key);
                return (
                  <Fragment key={g.key}>
                    <tr className="group-row">
                      <td><button type="button" className="button button--ghost button--icon" aria-expanded={expanded} aria-label={t("scans.history")} onClick={() => toggle(g.key)}>{expanded ? <ChevronDown /> : <ChevronRight />}</button></td>
                      <td><Link className="row-link" to={`/scans/${last.id}`}>{g.name}</Link> {g.runs.length > 1 && <Badge tone="primary">{t("scans.runsCount", { n: g.runs.length })}</Badge>}</td>
                      <td><StatusBadge status={last.status} /></td>
                      <td>{formatDate(last.queued_at, locale)}</td>
                      <td>
                        <strong>{nc(last) ?? "—"}</strong>
                        {delta != null && delta !== 0 && <span className={`trend ${delta > 0 ? "trend--bad" : "trend--good"}`} title={t("scans.trend")}>{delta > 0 ? <TrendingUp size={14} /> : <TrendingDown size={14} />}{delta > 0 ? `+${delta}` : delta}</span>}
                      </td>
                      <td><div className="row-actions">
                        {g.definitionId && <Button size="sm" onClick={() => onRescan(g.definitionId as string)}><RotateCcw />{t("scans.rescan")}</Button>}
                        {reportButton(last)}
                      </div></td>
                    </tr>
                    {expanded && g.runs.map((r) => (
                      <tr key={r.id} className="history-row">
                        <td />
                        <td><Link className="row-link" to={`/scans/${r.id}`}>{formatDate(r.queued_at, locale)}</Link>{r.schedule_id && <span className="ml-2 text-xs text-muted">⏱</span>}</td>
                        <td><StatusBadge status={r.status} /></td>
                        <td className="text-muted">{formatDuration(r.duration_seconds)}</td>
                        <td>{nc(r) ?? "—"}</td>
                        <td>{runActions(r)}</td>
                      </tr>
                    ))}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
