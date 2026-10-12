import { Activity, AlertTriangle, CheckCircle2, Server, ShieldCheck, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Dashboard as Data } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Empty, ErrorNote, Metric, PageHeader, useLoad } from "../components/common";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Select } from "../components/ui/input";
import { RecentRuns } from "../components/RecentRuns";
import { useI18n } from "../i18n";
import { formatDate } from "../lib/utils";
import { useState } from "react";
import type { SI, Tag } from "../api/types";

export default function Dashboard() {
  const { t, locale } = useI18n();
  const { atLeast } = useAuth();
  const [scope, setScope] = useState<"mine" | "all">("mine");
  const [tag, setTag] = useState("");
  const [si, setSi] = useState("");
  const { data, error } = useLoad(() => api<Data>("/dashboard", { params: { scope, tag, si } }), [scope, tag, si], 10000);
  const { data: tags } = useLoad(() => api<Tag[]>("/tags"));
  const { data: systems } = useLoad(() => api<SI[]>("/information-systems"));
  const counts = data?.counts ?? {};
  const trend = data?.compliance_trend ?? [];
  const max = Math.max(1, ...trend.map((p) => p.compliant + p.non_compliant));
  const posture = data?.posture;
  const grades = Object.entries(posture?.grades ?? {});
  const gradeMax = Math.max(1, ...grades.map(([, n]) => n));
  return (
    <>
      <PageHeader title={t("nav.dashboard")} actions={
        <>
          {atLeast("OPERATOR") && <Select aria-label={t("dash.scope")} value={scope} onChange={(e) => setScope(e.target.value as "mine" | "all")} className="w-44"><option value="mine">{t("dash.scopeMine")}</option><option value="all">{t("dash.scopeAll")}</option></Select>}
          <Select aria-label="SI" value={si} onChange={(e) => setSi(e.target.value)} className="w-60"><option value="">{t("filter.allSi")}</option>{systems?.map((s) => <option key={s.id} value={s.id}>{s.parent_id ? "↳ " : ""}{s.name}</option>)}</Select>
          <Select aria-label="Tag" value={tag} onChange={(e) => setTag(e.target.value)} className="w-40"><option value="">{t("filter.allTags")}</option>{tags?.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</Select>
        </>
      } />
      <ErrorNote error={error} />
      <section className="dash-section" aria-label={t("dash.section.posture")}>
        <h2 className="dash-heading">{t("dash.section.posture")}</h2>
        <div className="metrics">
          <Metric label={t("dash.rate")} value={posture && posture.endpoints ? `${Math.round((posture.compliant / posture.endpoints) * 100)} %` : "—"} hint={posture?.endpoints ? t("dash.rateHint", { n: posture.compliant, total: posture.endpoints }) : t("dash.noData")} icon={<ShieldCheck size={18} />} tone="green" />
          <Metric label={t("dash.urgent")} value={posture ? posture.critical + posture.high : "—"} hint={posture ? t("dash.urgentHint", { c: posture.critical, h: posture.high }) : undefined} icon={<AlertTriangle size={18} />} tone={posture && posture.critical + posture.high ? "red" : "amber"} />
          <Metric label={t("dash.endpoints")} value={posture?.endpoints ?? "—"} hint={posture ? t("dash.endpointsHint", { n: posture.scans }) : undefined} icon={<Server size={18} />} tone="blue" />
        </div>
        <div className="dash-grid">
          <Card>
            <CardHeader><CardTitle>{t("dash.trend")}</CardTitle></CardHeader>
            <CardContent>
              {trend.length ? (
                <div className="dash-chart" role="img" aria-label={t("dash.trend")}>
                  {trend.map((p) => (
                    <Link key={p.run_id} to={`/scans/${p.run_id}`} title={`${p.name}: ${p.compliant}/${p.compliant + p.non_compliant}`} className="dash-bar" style={{ height: `${((p.compliant + p.non_compliant) / max) * 100}%` }}>
                      <span className="bg-danger" style={{ flex: p.non_compliant }} /><span className="bg-success" style={{ flex: p.compliant }} />
                    </Link>
                  ))}
                </div>
              ) : <p className="text-sm text-muted">{t("dash.noTrend")}</p>}
              <div className="stacked-legend mt-4"><span><i className="stacked-dot ok" />{t("dash.compliant")}</span><span><i className="stacked-dot bad" />{t("dash.nonCompliant")}</span></div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>{t("dash.grades")}</CardTitle></CardHeader>
            <CardContent>
              {grades.length ? (
                <ul className="dash-grades">
                  {grades.map(([grade, n]) => (
                    <li key={grade}><span className="dash-grade">{grade}</span><span className="dash-grade-bar"><i style={{ width: `${(n / gradeMax) * 100}%` }} /></span><span className="dash-grade-n">{n}</span></li>
                  ))}
                </ul>
              ) : <p className="text-sm text-muted">{t("dash.noGrades")}</p>}
            </CardContent>
          </Card>
        </div>
      </section>
      <section className="dash-section" aria-label={t("dash.section.activity")}>
        <h2 className="dash-heading">{t("dash.section.activity")}</h2>
        <div className="metrics">
          <Metric label={t("dash.running")} value={(counts.running ?? 0) + (counts.queued ?? 0)} icon={<Activity size={18} />} to="/scans" />
          <Metric label={t("dash.completed")} value={(counts.completed ?? 0) + (counts.partial ?? 0)} icon={<CheckCircle2 size={18} />} tone="green" to="/scans" />
          <Metric label={t("dash.failed")} value={(counts.failed ?? 0) + (counts.expired ?? 0)} icon={<XCircle size={18} />} tone="red" to="/scans" />
        </div>
        <div className="dash-grid dash-grid--wide">
          <Card>
            <CardHeader><CardTitle>{t("dash.recent")}</CardTitle></CardHeader>
            {data?.recent.length ? <RecentRuns runs={data.recent} /> : <Empty>{t("dash.noScans")}</Empty>}
          </Card>
          <Card>
            <CardHeader><CardTitle>{t("dash.upcoming")}</CardTitle></CardHeader>
            <CardContent className="dash-list">
              {data?.upcoming.length ? data.upcoming.map((s) => <div key={s.id} className="dash-row"><span>{s.kind}</span><span className="text-muted">{formatDate(s.next_run_at, locale)}</span></div>) : <p className="text-sm text-muted">{t("dash.noUpcoming")}</p>}
            </CardContent>
          </Card>
        </div>
      </section>
    </>
  );
}
