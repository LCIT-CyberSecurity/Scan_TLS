import { Download } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, downloadUrl } from "../api/client";
import type { Run, SI, Tag } from "../api/types";
import { Empty, ErrorNote, PageHeader, StatusBadge, useLoad } from "../components/common";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Select } from "../components/ui/input";
import { DataTable, type Column } from "../components/DataTable";
import { useI18n } from "../i18n";
import { formatDate } from "../lib/utils";

export default function Reports() {
  const { t, locale } = useI18n();
  const [tag, setTag] = useState("");
  const [si, setSi] = useState("");
  const { data, error } = useLoad(() => api<Run[]>("/scan-runs", { params: { tag, si, limit: "200" } }), [tag, si]);
  const { data: tags } = useLoad(() => api<Tag[]>("/tags"));
  const { data: systems } = useLoad(() => api<SI[]>("/information-systems"));
  const rows = data?.filter((r) => r.reports.length) ?? [];
  const columns: Column<Run>[] = [
    { key: "name", header: t("col.name"), values: (r) => [r.name], sort: (r) => r.name, render: (r) => <Link to={`/scans/${r.id}`} className="row-link">{r.name}</Link> },
    { key: "date", header: t("col.date"), sort: (r) => r.finished_at ?? "", values: (r) => (r.finished_at ? [new Date(r.finished_at).toLocaleDateString(locale)] : []), render: (r) => formatDate(r.finished_at, locale) },
    { key: "status", header: t("col.status"), values: (r) => [r.status], render: (r) => <StatusBadge status={r.status} /> },
    { key: "nc", header: t("col.nonCompliant"), sort: (r) => r.summary?.non_compliant_endpoints ?? -1, values: (r) => [String(r.summary?.non_compliant_endpoints ?? "—")], render: (r) => r.summary?.non_compliant_endpoints ?? "—" },
    { key: "pol", header: t("pol.policies"), values: (r) => r.policy_versions.map((p) => `${p.name} v${p.version}`), render: (r) => <span className="text-xs">{r.policy_versions.map((p) => `${p.name} v${p.version}`).join(", ")}</span> },
    { key: "reports", header: t("nav.reports"), render: (r) => <div className="flex flex-wrap gap-1">{r.reports.filter((x) => ["html", "md", "csv", "cbom"].includes(x.format)).map((x) => <Button key={x.format} size="sm" variant="outline" asChild><a href={downloadUrl(r.id, x.format)}><Download />{x.format.toUpperCase()}</a></Button>)}</div> },
  ];
  return (
    <>
      <PageHeader title={t("nav.reports")} actions={
        <>
          <Select aria-label="SI" className="w-60" value={si} onChange={(e) => setSi(e.target.value)}><option value="">{t("filter.allSi")}</option>{systems?.map((s) => <option key={s.id} value={s.id}>{s.parent_id ? "↳ " : ""}{s.name}</option>)}</Select>
          <Select aria-label="Tag" className="w-40" value={tag} onChange={(e) => setTag(e.target.value)}><option value="">{t("filter.allTags")}</option>{tags?.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</Select>
        </>
      } />
      <ErrorNote error={error} />
      <Card>{rows.length ? <DataTable rows={rows} rowKey={(r) => r.id} columns={columns} /> : <Empty>{t("reports.none")}</Empty>}</Card>
    </>
  );
}
