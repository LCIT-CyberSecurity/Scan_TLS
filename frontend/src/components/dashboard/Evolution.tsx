import { Link } from "react-router-dom";
import type { Evolution as Data, EvolutionRun } from "../../api/types";
import { useI18n } from "../../i18n";
import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Input } from "../ui/input";

const LEVELS = ["critical", "high", "medium", "low"] as const;
const TONE = { critical: "danger", high: "danger", medium: "warning", low: "neutral" } as const;
const W = 640, H = 170, PAD = { l: 36, r: 12, t: 10, b: 28 };

function Series({ runs }: { runs: EvolutionRun[] }) {
  const { t, locale } = useI18n();
  const tr = t as unknown as (k: string, v?: Record<string, string | number>) => string;
  const max = Math.max(1, ...runs.map((r) => LEVELS.reduce((n, lv) => n + r.findings[lv], 0)));
  const slot = (W - PAD.l - PAD.r) / runs.length;
  const bar = Math.min(48, slot * 0.7);
  const scale = (n: number) => (n * (H - PAD.t - PAD.b)) / max;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="evo-chart" role="img" aria-label={t("evo.series")}>
      <line x1={PAD.l} x2={W - PAD.r} y1={H - PAD.b} y2={H - PAD.b} className="trend-grid" />
      <text x={PAD.l - 6} y={PAD.t + 8} textAnchor="end" className="trend-axis">{max}</text>
      <text x={PAD.l - 6} y={H - PAD.b} textAnchor="end" className="trend-axis">0</text>
      {runs.map((r, i) => {
        let y = H - PAD.b;
        const cx = PAD.l + slot * i + slot / 2;
        const total = LEVELS.reduce((n, lv) => n + r.findings[lv], 0);
        return (
          <g key={r.run_id}>
            <title>{`${r.name} · ${new Date(r.finished_at).toLocaleDateString(locale)} · ${LEVELS.map((lv) => `${tr(`evo.sev.${lv}`)} ${r.findings[lv]}`).join(" · ")}`}</title>
            {LEVELS.map((lv) => { const h = scale(r.findings[lv]); y -= h; return h > 0 ? <rect key={lv} x={cx - bar / 2} y={y} width={bar} height={h} className={`evo-bar evo-bar--${lv}`} /> : null; })}
            <text x={cx} y={H - PAD.b - scale(total) - 4} textAnchor="middle" className="trend-axis">{total}</text>
            {(runs.length <= 8 || i % Math.ceil(runs.length / 8) === 0) && <text x={cx} y={H - 10} textAnchor="middle" className="trend-axis">{new Date(r.finished_at).toLocaleDateString(locale, { day: "2-digit", month: "short" })}</text>}
          </g>
        );
      })}
    </svg>
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
        {data && data.series.length > 0 && <div><h3 className="text-sm font-semibold">{t("evo.series")}</h3><Series runs={data.series} />
          <p className="dash-note">{LEVELS.map((lv) => <span key={lv} className="evo-legend"><i className={`evo-bar evo-bar--${lv}`} />{tr(`evo.sev.${lv}`)}</span>)}</p></div>}
      </CardContent>
    </Card>
  );
}
