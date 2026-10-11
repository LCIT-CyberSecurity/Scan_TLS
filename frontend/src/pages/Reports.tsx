import { Download } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, downloadUrl } from "../api/client";
import type { Run, SI, Tag } from "../api/types";
import { Empty, ErrorNote, PageHeader, StatusBadge, useLoad } from "../components/common";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Select } from "../components/ui/input";
import { Table, Td, Th } from "../components/ui/table";
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
  return (
    <>
      <PageHeader title={t("nav.reports")} actions={
        <>
          <Select aria-label="SI" className="w-60" value={si} onChange={(e) => setSi(e.target.value)}><option value="">{t("filter.allSi")}</option>{systems?.map((s) => <option key={s.id} value={s.id}>{s.parent_id ? "↳ " : ""}{s.name}</option>)}</Select>
          <Select aria-label="Tag" className="w-40" value={tag} onChange={(e) => setTag(e.target.value)}><option value="">{t("filter.allTags")}</option>{tags?.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</Select>
        </>
      } />
      <ErrorNote error={error} />
      <Card>{rows.length ? (
        <Table><thead><tr><Th>{t("col.name")}</Th><Th>{t("col.date")}</Th><Th>{t("col.status")}</Th><Th>{t("col.nonCompliant")}</Th><Th>{t("pol.policies")}</Th><Th>{t("nav.reports")}</Th></tr></thead>
          <tbody>{rows.map((r) => (
            <tr key={r.id}><Td><Link to={`/scans/${r.id}`} className="row-link">{r.name}</Link></Td><Td>{formatDate(r.finished_at, locale)}</Td><Td><StatusBadge status={r.status} /></Td><Td>{r.summary?.non_compliant_endpoints ?? "—"}</Td>
              <Td className="text-xs">{r.policy_versions.map((p) => `${p.name} v${p.version}`).join(", ")}</Td>
              <Td><div className="flex flex-wrap gap-1">{r.reports.filter((x) => ["html", "md", "csv", "cbom"].includes(x.format)).map((x) => <Button key={x.format} size="sm" variant="outline" asChild><a href={downloadUrl(r.id, x.format)}><Download />{x.format.toUpperCase()}</a></Button>)}</div></Td></tr>
          ))}</tbody></Table>
      ) : <Empty>{t("reports.none")}</Empty>}</Card>
    </>
  );
}
