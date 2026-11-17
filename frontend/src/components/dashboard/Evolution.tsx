import { Link, useNavigate } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Evolution as Data, EvolutionRun } from "../../api/types";
import { useI18n } from "../../i18n";
import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Input } from "../ui/input";

const LEVELS = ["critical", "high", "medium", "low"] as const;
const TONE = { critical: "danger", high: "danger", medium: "warning", low: "neutral" } as const;
function Series({ runs }: { runs: EvolutionRun[] }) {
  const { t, locale } = useI18n();
  const navigate = useNavigate();
  const tr = t as unknown as (k: string, v?: Record<string, string | number>) => string;
  const data = runs.map((run) => ({ ...run, label: new Date(run.finished_at).toLocaleDateString(locale, { day: "2-digit", month: "short" }), fullDate: new Date(run.finished_at).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" }) }));
  const openRun = (index: number) => { const run = runs[index]; if (run) void navigate(`/scans/${run.run_id}`); };
  return (
    <>
      <div className="rechart-frame rechart-frame--evolution" role="group" aria-label={t("evo.series")}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 12, right: 14, bottom: 4, left: 0 }} barCategoryGap="28%">
            <CartesianGrid vertical={false} stroke="var(--hairline)" strokeDasharray="3 5" />
            <XAxis dataKey="label" tick={{ fill: "var(--text-faint)", fontSize: 11 }} tickLine={false} axisLine={false} minTickGap={18} />
            <YAxis allowDecimals={false} width={38} tick={{ fill: "var(--text-faint)", fontSize: 11 }} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={{ background: "var(--surface)", borderColor: "var(--border-strong)", borderRadius: 10, color: "var(--text-primary)", boxShadow: "var(--shadow-lg)" }} labelFormatter={(_label, payload) => {
              const run = payload?.[0]?.payload as (typeof data)[number] | undefined;
              return run ? `${run.name} · ${run.fullDate}` : "";
            }} formatter={(value, name) => [Number(value).toLocaleString(locale), String(name)]} />
            {LEVELS.map((level) => <Bar key={level} dataKey={`findings.${level}`} name={tr(`evo.sev.${level}`)} stackId="findings" fill={`var(--evo-${level})`} radius={level === "low" ? [3, 3, 0, 0] : undefined} isAnimationActive={false} cursor="pointer" onClick={(_entry, index) => openRun(index)} />)}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="evo-chart-legend" aria-label={t("evo.severity")}>
        {LEVELS.map((level) => <span key={level}><i className={`evo-chart-legend__swatch evo-chart-legend__swatch--${level}`} />{tr(`evo.sev.${level}`)}</span>)}
      </div>
      <details className="chart-data">
        <summary>{t("dash.chartData")}</summary>
        <div className="table-scroll"><table className="simple-table">
          <thead><tr><th>{t("col.name")}</th><th>{t("col.date")}</th>{LEVELS.map((level) => <th key={level}>{tr(`evo.sev.${level}`)}</th>)}</tr></thead>
          <tbody>{data.map((run) => <tr key={run.run_id}><td><Link to={`/scans/${run.run_id}`}>{run.name}</Link></td><td>{run.fullDate}</td>{LEVELS.map((level) => <td key={level}>{run.findings[level]}</td>)}</tr>)}</tbody>
        </table></div>
      </details>
    </>
  );
}

/** What changed for one scan definition between two dates: comparison of the reference scans, and the findings per scan in between. */
export function Evolution({ data, from, to, onRange }: { data: Data | undefined; from: string; to: string; onRange: (from: string, to: string) => void }) {
  const { t, locale } = useI18n();
  const tr = t as unknown as (k: string, v?: Record<string, string | number>) => string;
  const stamp = (r: EvolutionRun) => new Date(r.finished_at).toLocaleDateString(locale, { dateStyle: "medium" });
  const cmp = data?.comparison;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("evo.title")}</CardTitle>
        <div className="evo-range">
          <label>{t("evo.from")}<Input type="date" aria-label={t("evo.from")} value={from} max={to || undefined} onChange={(e) => onRange(e.target.value, to)} /></label>
          <label>{t("evo.to")}<Input type="date" aria-label={t("evo.to")} value={to} min={from || undefined} onChange={(e) => onRange(from, e.target.value)} /></label>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {!data && <p className="text-sm text-muted">{t("dash.noTrend")}</p>}
        {data && data.status === "invalid_range" && <p className="text-sm text-danger">{t("evo.invalid")}</p>}
        {data && data.status === "no_runs" && <p className="text-sm text-muted">{t("evo.noRuns")}</p>}
        {data && data.status === "single_run" && data.to_run && <p className="text-sm text-muted">{t("evo.single", { date: stamp(data.to_run) })}</p>}
        {data && data.status === "ok" && data.from_run && data.to_run && cmp && (
          <>
            <p className="text-sm">
              <Link to={`/scans/${data.from_run.run_id}`}>{stamp(data.from_run)}</Link> → <Link to={`/scans/${data.to_run.run_id}`}>{stamp(data.to_run)}</Link>
              {" · "}<Link to={`/scans/${data.to_run.run_id}?compare=${data.from_run.run_id}`} className="text-muted">{t("evo.open")}</Link>
            </p>
            {cmp.warnings.map((w) => <p key={w} className="dash-note dash-note--warn">{tr(`evo.warn.${w}`)}</p>)}
            <div className="evo-tiles">
              {(["new", "fixed", "persistent", "not_retested"] as const).map((k) => (
                <div key={k} className={`evo-tile evo-tile--${k}`}><strong>{cmp.counts[k]}</strong><span>{tr(`evo.${k}`)}</span></div>
              ))}
            </div>
            <table className="simple-table" aria-label={t("evo.bySeverity")}>
              <thead><tr><th>{t("evo.severity")}</th><th>{stamp(data.from_run)}</th><th>{stamp(data.to_run)}</th><th>Δ</th></tr></thead>
              <tbody>{LEVELS.map((lv) => {
                const before = data.from_run!.findings[lv], after = data.to_run!.findings[lv], delta = after - before;
                return <tr key={lv}><td><Badge tone={TONE[lv]}>{tr(`evo.sev.${lv}`)}</Badge></td><td>{before}</td><td>{after}</td><td className={delta > 0 ? "text-danger" : delta < 0 ? "text-success" : "text-muted"}>{delta > 0 ? `+${delta}` : delta}</td></tr>;
              })}</tbody>
            </table>
            <p className="text-sm text-muted">
              {t("evo.endpoints", { added: cmp.endpoints_added, removed: cmp.endpoints_removed })} · {t("evo.compliance", { improved: cmp.compliance.improved, degraded: cmp.compliance.degraded })}
              {cmp.certificate_changes.length > 0 && <> · {t("evo.certs", { n: cmp.certificate_changes.length })}</>}
            </p>
            {(["new", "fixed"] as const).map((k) => cmp[k].length > 0 && (
              <div key={k}>
                <h3 className="text-sm font-semibold">{tr(`evo.list.${k}`)}</h3>
                <ul className="dash-list">{cmp[k].map((f) => <li key={f.finding_id} className="dash-row"><span><Badge tone={TONE[f.severity as keyof typeof TONE] ?? "neutral"}>{f.severity}</Badge> {f.title || f.finding_id}</span><span className="text-muted">{t("evo.endpointsN", { n: f.endpoints })}</span></li>)}</ul>
              </div>
            ))}
          </>
        )}
        {data && data.series.length > 0 && <div className="evo-series"><h3 className="text-sm font-semibold">{t("evo.series")}</h3><Series runs={data.series} /></div>}
      </CardContent>
    </Card>
  );
}
