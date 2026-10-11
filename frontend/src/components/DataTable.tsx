import { ArrowDown, ArrowUp, ArrowUpDown, Filter, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useI18n } from "../i18n";
import { Empty } from "./common";
import { Table } from "./ui/table";

export interface Column<T> {
  key: string;
  header: ReactNode;
  /** Cell content. */
  render: (row: T) => ReactNode;
  /** Text values used to filter (several for multi-valued cells such as tags). Omit for a non-filterable column. */
  values?: (row: T) => string[];
  /** Sort key; defaults to the joined filter values. Omit both for a non-sortable column. */
  sort?: (row: T) => string | number;
  className?: string;
}

type Dir = "asc" | "desc";
const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

function FilterPopover({ anchor, options, selected, onChange, onClose }: { anchor: HTMLElement; options: string[]; selected: Set<string>; onChange: (next: Set<string>) => void; onClose: () => void }) {
  const { t } = useI18n();
  const [q, setQ] = useState("");
  const ref = useRef<HTMLDivElement>(null);
  const rect = anchor.getBoundingClientRect();
  const left = Math.max(8, Math.min(rect.left, window.innerWidth - 268));
  useEffect(() => {
    const down = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node) && !anchor.contains(e.target as Node)) onClose(); };
    const key = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("mousedown", down); document.addEventListener("keydown", key);
    return () => { document.removeEventListener("mousedown", down); document.removeEventListener("keydown", key); };
  }, [anchor, onClose]);
  const shown = options.filter((o) => o.toLowerCase().includes(q.toLowerCase()));
  const toggle = (o: string) => { const next = new Set(selected); if (next.has(o)) next.delete(o); else next.add(o); onChange(next); };
  return createPortal(
    <div ref={ref} className="filter-pop" role="dialog" style={{ top: rect.bottom + 6, left }}>
      <input autoFocus type="search" className="compact" placeholder={t("action.search")} aria-label={t("action.search")} value={q} onChange={(e) => setQ(e.target.value)} />
      <div className="filter-pop__list">
        {shown.map((o) => <label key={o}><input type="checkbox" checked={selected.has(o)} onChange={() => toggle(o)} /><span>{o || "—"}</span></label>)}
        {!shown.length && <span className="muted">—</span>}
      </div>
      <div className="filter-pop__foot">
        <button type="button" className="button button--ghost button--sm" onClick={() => onChange(new Set(shown))}>{t("table.selectAll")}</button>
        <button type="button" className="button button--ghost button--sm" onClick={() => onChange(new Set())}>{t("table.clear")}</button>
      </div>
    </div>,
    document.body,
  );
}

/** Table whose headers sort on click and open a value filter (checkbox list) on the funnel button. */
export function DataTable<T>({ rows, columns, rowKey, empty }: { rows: T[]; columns: Column<T>[]; rowKey: (row: T) => string; empty?: ReactNode }) {
  const { t } = useI18n();
  const [sort, setSort] = useState<{ key: string; dir: Dir } | null>(null);
  const [filters, setFilters] = useState<Record<string, Set<string>>>({});
  const [open, setOpen] = useState<{ key: string; anchor: HTMLElement } | null>(null);

  const options = useMemo(() => Object.fromEntries(columns.filter((c) => c.values).map((c) => [c.key, [...new Set(rows.flatMap((r) => c.values!(r)))].sort(collator.compare)])), [rows, columns]);
  const visible = useMemo(() => {
    let out = rows.filter((r) => columns.every((c) => { const f = filters[c.key]; return !f || !f.size || !c.values || c.values(r).some((v) => f.has(v)); }));
    const col = columns.find((c) => c.key === sort?.key);
    if (col && sort) {
      const get = col.sort ?? ((r: T) => (col.values?.(r) ?? []).join(", "));
      out = [...out].sort((a, b) => { const x = get(a), y = get(b); const c = typeof x === "number" && typeof y === "number" ? x - y : collator.compare(String(x), String(y)); return sort.dir === "asc" ? c : -c; });
    }
    return out;
  }, [rows, columns, filters, sort]);

  const activeFilters = Object.values(filters).filter((f) => f.size).length;
  const cycle = (key: string) => setSort((s) => (s?.key !== key ? { key, dir: "asc" } : s.dir === "asc" ? { key, dir: "desc" } : null));
  const openCol = open && columns.find((c) => c.key === open.key);

  return (
    <>
      <Table>
        <thead><tr>{columns.map((c) => {
          const sortable = !!(c.sort || c.values); const active = sort?.key === c.key; const filtered = !!filters[c.key]?.size;
          return (
            <th key={c.key} aria-sort={active ? (sort!.dir === "asc" ? "ascending" : "descending") : undefined} className={c.className}>
              <span className="th-inner">
                {sortable ? <button type="button" className="th-sort" onClick={() => cycle(c.key)}>{c.header}{active ? (sort!.dir === "asc" ? <ArrowUp size={13} /> : <ArrowDown size={13} />) : <ArrowUpDown size={13} className="th-idle" />}</button> : c.header}
                {c.values && <button type="button" className={`th-filter${filtered ? " active" : ""}`} aria-label={t("table.filter")} aria-pressed={filtered} onClick={(e) => setOpen(open?.key === c.key ? null : { key: c.key, anchor: e.currentTarget })}><Filter size={13} /></button>}
              </span>
            </th>
          );
        })}</tr></thead>
        <tbody>{visible.map((r) => <tr key={rowKey(r)}>{columns.map((c) => <td key={c.key} className={c.className}>{c.render(r)}</td>)}</tr>)}</tbody>
      </Table>
      {!visible.length && <Empty>{empty ?? "—"}</Empty>}
      {(activeFilters > 0 || visible.length !== rows.length) && (
        <div className="table-foot"><span>{t("table.count", { shown: visible.length, total: rows.length })}</span><button type="button" className="button button--ghost button--sm" onClick={() => { setFilters({}); setSort(null); }}><X size={13} />{t("table.reset")}</button></div>
      )}
      {open && openCol && <FilterPopover anchor={open.anchor} options={options[open.key] ?? []} selected={filters[open.key] ?? new Set()} onChange={(next) => setFilters((f) => ({ ...f, [open.key]: next }))} onClose={() => setOpen(null)} />}
    </>
  );
}
