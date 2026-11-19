import { useMemo, useState, type KeyboardEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Trend, TrendPoint } from "../../api/types";
import { useI18n } from "../../i18n";
import { Select } from "../ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

type PlotPoint = TrendPoint & { label: string; fullDate: string };

/** Compliance rate of successive runs for one scan definition. Unevaluated runs remain gaps, never zeroes. */
export function ComplianceTrend({ trend, onDefinition }: { trend: Trend | undefined; onDefinition: (id: string) => void }) {
  const { t, locale } = useI18n();
  const navigate = useNavigate();
  const [focus, setFocus] = useState<string | null>(null);
  const points = trend?.points ?? [];
  const sameDay = new Set(points.map((p) => p.finished_at.slice(0, 10))).size === 1;
  const dateOf = (date: string) => new Date(date).toLocaleString(locale, sameDay ? { hour: "2-digit", minute: "2-digit" } : { day: "2-digit", month: "short" });
  const data = useMemo<PlotPoint[]>(() => points.map((point) => ({
    ...point,
    label: dateOf(point.finished_at),
    fullDate: new Date(point.finished_at).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" }),
  })), [points, locale, sameDay]);
  const shown = points.find((point) => point.run_id === focus) ?? points[points.length - 1];
  const openPoint = (point?: PlotPoint) => { if (point) void navigate(`/scans/${point.run_id}`); };
  const keys = (event: KeyboardEvent<SVGGElement>, point: PlotPoint) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openPoint(point); }
  };
  const dot = (props: { cx?: number; cy?: number; payload?: PlotPoint }) => {
    const point = props.payload;
    if (props.cx == null || props.cy == null || !point || point.rate == null) return null;
    const label = `${point.name} · ${point.fullDate} · ${t("dash.trendRate", { rate: point.rate.toLocaleString(locale), c: point.compliant, e: point.evaluated })}`;
    return <g role="link" tabIndex={0} aria-label={label} className="trend-dot" onMouseEnter={() => setFocus(point.run_id)} onFocus={() => setFocus(point.run_id)} onClick={() => openPoint(point)} onKeyDown={(event) => keys(event, point)}>
      <circle cx={props.cx} cy={props.cy} r={11} fill="transparent" />
      <circle cx={props.cx} cy={props.cy} r={focus === point.run_id ? 5.5 : 4.5} fill={point.comparable ? "var(--chart-trend)" : "var(--surface)"} stroke="var(--chart-trend)" strokeWidth={2.5} pointerEvents="none"><title>{label}</title></circle>
    </g>;
  };
  return (
    <Card className="dash-chart-card">
      <CardHeader>
        <div><p className="dash-card-eyebrow">{t("dash.section.posture")}</p><CardTitle>{t("dash.trend")}</CardTitle></div>
        {(trend?.definitions.length ?? 0) > 1 && (
          <Select aria-label={t("dash.trendDef")} value={trend?.definition_id ?? ""} onChange={(event) => onDefinition(event.target.value)} className="trend-select">
            {trend?.definitions.map((definition) => <option key={definition.id} value={definition.id}>{definition.name} ({definition.runs})</option>)}
          </Select>
        )}
      </CardHeader>
      <CardContent>
        {data.length ? (
          <>
            <div className="rechart-frame rechart-frame--trend" role="group" aria-label={t("dash.trend")}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data} margin={{ top: 12, right: 14, bottom: 4, left: 0 }}>
                  <CartesianGrid vertical={false} stroke="var(--hairline)" strokeDasharray="3 5" />
                  <XAxis dataKey="label" tick={{ fill: "var(--text-faint)", fontSize: 11 }} tickLine={false} axisLine={false} minTickGap={24} />
                  <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tickFormatter={(value) => `${value}%`} width={48} tick={{ fill: "var(--text-faint)", fontSize: 11 }} tickLine={false} axisLine={false} />
                  <ReferenceLine y={100} stroke="var(--hairline)" />
                  <Tooltip contentStyle={{ background: "var(--surface)", borderColor: "var(--border-strong)", borderRadius: 10, color: "var(--text-primary)", boxShadow: "var(--shadow-lg)" }} labelFormatter={(_label, payload) => String((payload?.[0]?.payload as PlotPoint | undefined)?.fullDate ?? "")} formatter={(value, _name, item) => {
                    const point = item.payload as PlotPoint;
                    return [`${Number(value).toLocaleString(locale)} % · ${point.compliant}/${point.evaluated}`, t("dash.trend")];
                  }} />
                  <Line type="monotone" dataKey="rate" name={t("dash.trend")} stroke="var(--chart-trend)" strokeWidth={3} connectNulls={false} dot={dot} activeDot={false} isAnimationActive={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
            {shown && (
              <div className="trend-detail" aria-live="polite">
                <div><strong>{shown.name}</strong><span>{new Date(shown.finished_at).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" })}</span></div>
                <p>{shown.rate != null ? t("dash.trendRate", { rate: shown.rate.toLocaleString(locale), c: shown.compliant, e: shown.evaluated }) : t("dash.trendNone")} · {t("dash.trendTotal", { n: shown.total })}</p>
                {!shown.comparable && <p className="dash-note dash-note--warn">{t("dash.trendChanged")}</p>}
              </div>
            )}
            {points.some((point) => !point.comparable) && <p className="dash-note"><i className="trend-legend-dot" />{t("dash.trendChangedLegend")}</p>}
            <details className="chart-data">
              <summary>{t("dash.chartData")}</summary>
              <div className="table-scroll"><table className="simple-table">
                <thead><tr><th>{t("col.name")}</th><th>{t("col.date")}</th><th>{t("dash.trend")}</th><th>{t("dash.compliant")}</th><th>{t("dash.nonCompliant")}</th><th>{t("dash.totalEndpoints")}</th></tr></thead>
                <tbody>{data.map((point) => <tr key={point.run_id}><td><Link to={`/scans/${point.run_id}`} onMouseEnter={() => setFocus(point.run_id)} onFocus={() => setFocus(point.run_id)}>{point.name}</Link></td><td>{point.fullDate}</td><td>{point.rate == null ? t("dash.trendNone") : `${point.rate.toLocaleString(locale)} %`}</td><td>{point.compliant}</td><td>{point.non_compliant}</td><td>{point.total}</td></tr>)}</tbody>
              </table></div>
            </details>
          </>
        ) : <p className="text-sm text-muted">{t("dash.noTrend")}</p>}
      </CardContent>
    </Card>
  );
}
