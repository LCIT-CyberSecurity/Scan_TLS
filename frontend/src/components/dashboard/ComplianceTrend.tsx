import { useState } from "react";
import { Link } from "react-router-dom";
import type { Trend, TrendPoint } from "../../api/types";
import { Select } from "../ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { useI18n } from "../../i18n";

const W = 640, H = 280, PAD = { l: 44, r: 20, t: 16, b: 34 };
const GRID = [0, 25, 50, 75, 100];

/** Compliance rate (0-100 %) of the successive runs of ONE scan definition. Runs with nothing evaluated leave a gap, never a 0 %. */
export function ComplianceTrend({ trend, onDefinition }: { trend: Trend | undefined; onDefinition: (id: string) => void }) {
  const { t, locale } = useI18n();
  const points = trend?.points ?? [];
  const [focus, setFocus] = useState<string | null>(null);
  const x = (i: number) => PAD.l + (points.length < 2 ? (W - PAD.l - PAD.r) / 2 : (i * (W - PAD.l - PAD.r)) / (points.length - 1));
  const y = (rate: number) => PAD.t + ((100 - rate) * (H - PAD.t - PAD.b)) / 100;
  const dateOf = (p: TrendPoint) => new Date(p.finished_at).toLocaleDateString(locale, { day: "2-digit", month: "short" });
  const rated = points.map((p, i) => ({ p, i })).filter((q) => q.p.rate != null);
  // a line segment only joins two consecutive runs that both have a rate
  const segments = points.slice(1).map((b, i) => ({ a: points[i], ai: i, b, bi: i + 1 })).filter((q) => q.a.rate != null && q.b.rate != null);
  const shown = points.find((p) => p.run_id === focus) ?? points[points.length - 1];
  const labelEvery = Math.max(1, Math.ceil(points.length / 8));
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("dash.trend")}</CardTitle>
        {(trend?.definitions.length ?? 0) > 1 && (
          <Select aria-label={t("dash.trendDef")} value={trend?.definition_id ?? ""} onChange={(e) => onDefinition(e.target.value)} className="trend-select">
            {trend?.definitions.map((d) => <option key={d.id} value={d.id}>{d.name} ({d.runs})</option>)}
          </Select>
        )}
      </CardHeader>
      <CardContent>
        {points.length ? (
          <>
            <svg viewBox={`0 0 ${W} ${H}`} className="trend-chart" role="group" aria-label={t("dash.trend")}>
              {GRID.map((g) => (
                <g key={g}><line x1={PAD.l} x2={W - PAD.r} y1={y(g)} y2={y(g)} className="trend-grid" /><text x={PAD.l - 8} y={y(g) + 4} textAnchor="end" className="trend-axis">{g} %</text></g>
              ))}
              {segments.map(({ a, ai, b, bi }) => <line key={b.run_id} x1={x(ai)} y1={y(a.rate!)} x2={x(bi)} y2={y(b.rate!)} className="trend-line" />)}
              {points.map((p, i) => (i % labelEvery === 0 || i === points.length - 1) && <text key={`l${p.run_id}`} x={x(i)} y={H - 10} textAnchor="middle" className="trend-axis">{dateOf(p)}</text>)}
              {rated.map(({ p, i }) => (
                <Link key={p.run_id} to={`/scans/${p.run_id}`} aria-label={`${p.name} · ${dateOf(p)} · ${t("dash.trendRate", { rate: p.rate!, c: p.compliant, e: p.evaluated })}`}
                  onMouseEnter={() => setFocus(p.run_id)} onFocus={() => setFocus(p.run_id)}>
                  <circle cx={x(i)} cy={y(p.rate!)} r={focus === p.run_id ? 8 : 6} className={`trend-point${p.comparable ? "" : " trend-point--changed"}`}>
                    <title>{`${p.name} · ${dateOf(p)} · ${t("dash.trendRate", { rate: p.rate!, c: p.compliant, e: p.evaluated })}`}</title>
                  </circle>
                </Link>
              ))}
            </svg>
            {shown && (
              <p className="trend-detail" aria-live="polite">
                <strong>{shown.name}</strong> · {new Date(shown.finished_at).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" })}<br />
                {shown.rate != null ? t("dash.trendRate", { rate: shown.rate.toLocaleString(locale), c: shown.compliant, e: shown.evaluated }) : t("dash.trendNone")} · {t("dash.trendTotal", { n: shown.total })}
                {!shown.comparable && <span className="dash-note dash-note--warn">{t("dash.trendChanged")}</span>}
              </p>
            )}
            {points.some((p) => !p.comparable) && <p className="dash-note"><i className="trend-legend-dot" />{t("dash.trendChangedLegend")}</p>}
          </>
        ) : <p className="text-sm text-muted">{t("dash.noTrend")}</p>}
      </CardContent>
    </Card>
  );
}
