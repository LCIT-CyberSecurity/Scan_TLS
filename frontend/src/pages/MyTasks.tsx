import { CalendarClock, FileText, TriangleAlert, Activity } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Run, Schedule } from "../api/types";
import { Empty, PageHeader, StatusBadge, useLoad } from "../components/common";
import { Card, CardHeader, CardTitle } from "../components/ui/card";
import { useI18n } from "../i18n";
import { formatDate } from "../lib/utils";

function Block({ icon, title, to, children }: { icon: React.ReactNode; title: string; to: string; children: React.ReactNode }) {
  return <Card><CardHeader><CardTitle className="flex items-center gap-2 [&_svg]:size-4">{icon}{title}</CardTitle><Link to={to} className="text-sm text-primary hover:underline">→</Link></CardHeader><div className="divide-y divide-hairline">{children}</div></Card>;
}

// Shortcuts only: the full features live in Scans / Schedules / Reports.
export default function MyTasks() {
  const { t, locale } = useI18n();
  const { data: mine } = useLoad(() => api<Run[]>("/scan-runs", { params: { mine: true, limit: "30" } }), [], 10000);
  const { data: schedules } = useLoad(() => api<Schedule[]>("/schedules", { params: { mine: true } }));
  const running = mine?.filter((r) => r.status === "running" || r.status === "queued") ?? [];
  const failed = mine?.filter((r) => r.status === "failed" || r.status === "expired").slice(0, 5) ?? [];
  const reports = mine?.filter((r) => r.reports.length).slice(0, 5) ?? [];
  const row = (r: Run) => <Link key={r.id} to={`/scans/${r.id}`} className="flex items-center justify-between px-5 py-3 text-sm hover:bg-surface-2"><span>{r.name}</span><span className="flex items-center gap-3 text-muted"><StatusBadge status={r.status} />{formatDate(r.queued_at, locale)}</span></Link>;
  return (
    <>
      <PageHeader title={t("nav.tasks")} />
      <div className="grid gap-6 lg:grid-cols-2">
        <Block icon={<Activity />} title={t("tasks.running")} to="/scans">{running.length ? running.map(row) : <Empty>{t("tasks.none")}</Empty>}</Block>
        <Block icon={<TriangleAlert />} title={t("tasks.failed")} to="/scans">{failed.length ? failed.map(row) : <Empty>{t("tasks.none")}</Empty>}</Block>
        <Block icon={<FileText />} title={t("tasks.reports")} to="/reports">{reports.length ? reports.map(row) : <Empty>{t("tasks.none")}</Empty>}</Block>
        <Block icon={<CalendarClock />} title={t("tasks.upcoming")} to="/schedules">
          {schedules?.filter((s) => s.active).length ? schedules.filter((s) => s.active).slice(0, 5).map((s) => <div key={s.id} className="flex justify-between px-5 py-3 text-sm"><span>{s.kind}</span><span className="text-muted">{formatDate(s.next_run_at, locale)}</span></div>) : <Empty>{t("tasks.none")}</Empty>}
        </Block>
      </div>
    </>
  );
}
