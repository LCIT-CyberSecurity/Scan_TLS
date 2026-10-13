import { Activity, CheckCircle2, XCircle } from "lucide-react";
import { api } from "../api/client";
import type { Dashboard as Data } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Empty, ErrorNote, Metric, PageHeader, useLoad } from "../components/common";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Select } from "../components/ui/input";
import { RecentRuns } from "../components/RecentRuns";
import { ComplianceBreakdown } from "../components/dashboard/ComplianceBreakdown";
import { ComplianceTrend } from "../components/dashboard/ComplianceTrend";
import { SecurityKpis } from "../components/dashboard/SecurityKpis";
import { Evolution } from "../components/dashboard/Evolution";
import { Vigilance } from "../components/dashboard/Vigilance";
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
  const [trendDef, setTrendDef] = useState("");
  const [range, setRange] = useState(() => { const to = new Date(); const from = new Date(to.getTime() - 30 * 86400000); return { from: from.toISOString().slice(0, 10), to: to.toISOString().slice(0, 10) }; });
  const { data, error } = useLoad(() => api<Data>("/dashboard", { params: { scope, tag, si, trend_definition: trendDef, evolution_from: range.from, evolution_to: range.to } }), [scope, tag, si, trendDef, range], 10000);
  const { data: tags } = useLoad(() => api<Tag[]>("/tags"));
  const { data: systems } = useLoad(() => api<SI[]>("/information-systems"));
  const counts = data?.counts ?? {};
  const posture = data?.posture;
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
        <SecurityKpis posture={posture} />
        <div className="dash-grid">
          <ComplianceBreakdown posture={posture} />
          <ComplianceTrend trend={data?.trend} onDefinition={setTrendDef} />
        </div>
        <Evolution data={data?.evolution} from={range.from} to={range.to} onRange={(from, to) => setRange({ from, to })} />
        <Vigilance posture={posture} />
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
          <Card className="self-start">
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
