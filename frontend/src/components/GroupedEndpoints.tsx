import { ChevronDown, ChevronRight } from "lucide-react";
import { Fragment, useMemo, useState, type ReactNode } from "react";
import type { Endpoint } from "../api/types";
import { useI18n } from "../i18n";
import type { Column } from "./DataTable";
import { TagList } from "./common";
import { Badge } from "./ui/badge";

const GRADES = ["A+", "A", "B", "C", "D", "E", "F"];
const hostOf = (e: Endpoint) => e.hostname || e.ip_address;
const worstGrade = (list: Endpoint[]) => list.map((e) => e.grade).filter((g) => GRADES.includes(g)).sort((a, b) => GRADES.indexOf(b) - GRADES.indexOf(a))[0] ?? "—";

/** Endpoints of the same host (several ports) on one row with a chevron; a host with a single endpoint stays a plain row. */
export function GroupedEndpoints({ rows, columns }: { rows: Endpoint[]; columns: Column<Endpoint>[] }) {
  const { t } = useI18n();
  const [open, setOpen] = useState<Set<string>>(new Set());
  const groups = useMemo(() => {
    const map = new Map<string, Endpoint[]>();
    for (const e of rows) map.set(hostOf(e), [...(map.get(hostOf(e)) ?? []), e]);
    return [...map.entries()];
  }, [rows]);
  const toggle = (key: string) => setOpen((s) => { const n = new Set(s); if (n.has(key)) n.delete(key); else n.add(key); return n; });

  const summary = (key: string, list: Endpoint[]): ReactNode => {
    const nonCompliant = list.filter((e) => e.compliance_status === "non_compliant").length;
    const expiry = list.map((e) => String(e.certificate.valid_until ?? "")).filter(Boolean).sort()[0];
    switch (key) {
      case "tags": return list[0].tags?.length ? <TagList tags={list[0].tags} /> : "—";
      case "grade": return worstGrade(list);
      case "status": return nonCompliant ? <>{nonCompliant}/{list.length} non_compliant</> : list.every((e) => e.compliance_status === list[0].compliance_status) ? list[0].compliance_status : "—";
      case "tls": return [...new Set(list.flatMap((e) => e.tls_versions))].sort().join(", ");
      case "cert": return expiry ? <span className="text-xs text-muted">{expiry}</span> : "—";
      default: return null;
    }
  };

  return (
    <div className="table-scroll">
      <table className="simple-table">
        <thead><tr><th style={{ width: 36 }} />{columns.map((c) => <th key={c.key}>{c.header}</th>)}</tr></thead>
        <tbody>
          {groups.map(([host, list]) => {
            if (list.length === 1) return <tr key={host}><td />{columns.map((c) => <td key={c.key}>{c.render(list[0])}</td>)}</tr>;
            const expanded = open.has(host);
            return (
              <Fragment key={host}>
                <tr className="group-row">
                  <td><button type="button" className="button button--ghost button--icon" aria-expanded={expanded} aria-label={t("run.expandHost")} onClick={() => toggle(host)}>{expanded ? <ChevronDown /> : <ChevronRight />}</button></td>
                  {columns.map((c) => (
                    <td key={c.key}>{c.key === "endpoint" ? <><span className="row-link">{host}</span> <Badge tone="primary">{t("run.endpointsCount", { n: list.length })}</Badge></> : summary(c.key, list)}</td>
                  ))}
                </tr>
                {expanded && list.map((e) => <tr key={e.endpoint_id} className="history-row"><td />{columns.map((c) => <td key={c.key}>{c.render(e)}</td>)}</tr>)}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
