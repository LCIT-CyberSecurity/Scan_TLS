import { Download } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, downloadUrl } from "../api/client";
import type { Definition, Run, SI, Tag } from "../api/types";
import { Empty, ErrorNote, PageHeader, StatusBadge, useLoad } from "../components/common";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Select } from "../components/ui/input";
import { DataTable, type Column } from "../components/DataTable";
import { useI18n } from "../i18n";
import { formatDate } from "../lib/utils";
import { useAuth } from "../auth/AuthContext";

export default function Reports({ embedded = false }: { embedded?: boolean }) {
  const { t, locale } = useI18n();
  const { atLeast } = useAuth();
  const [searchParams] = useSearchParams();
  const canSeeDefinitions = atLeast("USER");
  const [tag, setTag] = useState(searchParams.get("tag") ?? "");
  const [si, setSi] = useState(searchParams.get("si") ?? "");
  const [definition, setDefinition] = useState(searchParams.get("definition_id") ?? "");
  const [status, setStatus] = useState(searchParams.get("status") ?? "");
  const [format, setFormat] = useState(searchParams.get("format") ?? "");
  const runId = searchParams.get("run_id") ?? "";
  const [from, setFrom] = useState(searchParams.get("from") ?? "");
  const [to, setTo] = useState(searchParams.get("to") ?? "");
  const { data, error } = useLoad(() => api<Run[]>("/scan-runs", { params: { tag, si, limit: "200" } }), [tag, si]);
  const { data: tags } = useLoad(() => api<Tag[]>("/tags"));
  const { data: systems } = useLoad(() => api<SI[]>("/information-systems"));
  const { data: definitions } = useLoad(() => canSeeDefinitions ? api<Definition[]>("/scan-definitions") : Promise.resolve([]), [canSeeDefinitions]);
  const definitionNames = useMemo(() => new Map((definitions ?? []).map((d) => [d.id, d.name])), [definitions]);
  const rows = (data ?? []).filter((r) => {
    if (!r.reports.length) return false;
    if (runId && r.id !== runId) return false;
    if (definition && r.definition_id !== definition) return false;
    if (status && r.status !== status) return false;
    if (format && !r.reports.some((report) => report.format === format)) return false;
    const date = r.finished_at?.slice(0, 10) ?? r.queued_at.slice(0, 10);
    return (!from || date >= from) && (!to || date <= to);
  });
  const columns: Column<Run>[] = [
    { key: "name", header: t("col.name"), values: (r) => [r.name], sort: (r) => r.name, render: (r) => <Link to={`/scans/${r.id}`} className="row-link">{r.name}</Link> },
    ...(canSeeDefinitions ? [{ key: "definition", header: t("scans.definitions"), values: (r: Run) => [definitionNames.get(r.definition_id ?? "") ?? ""], render: (r: Run) => r.definition_id && definitionNames.has(r.definition_id) ? <Link className="ref-link" to={`/scans?tab=scans&definition=${r.definition_id}`}>{definitionNames.get(r.definition_id)}</Link> : "—" } as Column<Run>] : []),
    { key: "date", header: t("col.date"), sort: (r) => r.finished_at ?? "", values: (r) => (r.finished_at ? [new Date(r.finished_at).toLocaleDateString(locale)] : []), render: (r) => formatDate(r.finished_at, locale) },
    { key: "status", header: t("col.status"), values: (r) => [r.status], render: (r) => <StatusBadge status={r.status} /> },
    { key: "nc", header: t("col.nonCompliant"), sort: (r) => r.summary?.non_compliant_endpoints ?? -1, values: (r) => [String(r.summary?.non_compliant_endpoints ?? "—")], render: (r) => r.summary?.non_compliant_endpoints ?? "—" },
    { key: "pol", header: t("pol.policies"), values: (r) => r.policy_versions.map((p) => `${p.name} v${p.version}`), render: (r) => <span className="text-xs">{r.policy_versions.map((p) => `${p.name} v${p.version}`).join(", ")}</span> },
    { key: "reports", header: t("nav.reports"), render: (r) => <div className="flex flex-wrap gap-1">{r.reports.filter((x) => format ? x.format === format : ["html", "md", "csv", "cbom", "findings_csv", "contextual_risk_csv", "mail_security_csv", "service_csv"].includes(x.format)).map((x) => {
      const html = x.format === "html";
      const label = x.format === "service_csv" ? "SERVICES CSV" : x.format === "mail_security_csv" ? "MAIL CSV" : x.format === "findings_csv" ? "FINDINGS CSV" : x.format === "contextual_risk_csv" ? "CONTEXTUAL RISK CSV" : x.format.toUpperCase();
      return <Button key={x.format} size="sm" variant="outline" asChild><a href={downloadUrl(r.id, x.format, html)} target={html ? "_blank" : undefined} rel={html ? "noreferrer" : undefined}><Download />{label}</a></Button>;
    })}</div> },
  ];
  return (
    <>
      {!embedded && <PageHeader title={t("nav.reports")} />}
      <div className="mb-3 flex flex-wrap items-center gap-3">
        {canSeeDefinitions && <Select aria-label={t("scans.definitions")} className="w-52" value={definition} onChange={(e) => setDefinition(e.target.value)}><option value="">{t("filter.allDefinitions")}</option>{definitions?.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</Select>}
        <Select aria-label={t("col.status")} className="w-44" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">{t("filter.allStatuses")}</option>{["queued", "running", "completed", "partial", "failed", "cancelled", "expired"].map((s) => <option key={s} value={s}>{t(`status.${s}` as never)}</option>)}</Select>
        <Select aria-label={t("filter.format")} className="w-40" value={format} onChange={(e) => setFormat(e.target.value)}><option value="">{t("filter.allFormats")}</option>{[...new Set((data ?? []).flatMap((r) => r.reports.map((report) => report.format)))].sort().map((value) => <option key={value} value={value}>{value === "service_csv" ? "SERVICES CSV" : value === "mail_security_csv" ? "MAIL CSV" : value.toUpperCase()}</option>)}</Select>
        <label className="flex items-center gap-2 text-sm">{t("filter.from")}<input aria-label={t("filter.from")} type="date" className="input w-auto" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
        <label className="flex items-center gap-2 text-sm">{t("filter.to")}<input aria-label={t("filter.to")} type="date" className="input w-auto" value={to} onChange={(e) => setTo(e.target.value)} /></label>
        <Select aria-label="SI" className="w-52" value={si} onChange={(e) => setSi(e.target.value)}><option value="">{t("filter.allSi")}</option>{systems?.map((s) => <option key={s.id} value={s.id}>{s.parent_id ? "↳ " : ""}{s.name}</option>)}</Select>
        <Select aria-label="Tag" className="w-40" value={tag} onChange={(e) => setTag(e.target.value)}><option value="">{t("filter.allTags")}</option>{tags?.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</Select>
      </div>
      <ErrorNote error={error} />
      <Card>{rows.length ? <DataTable rows={rows} rowKey={(r) => r.id} columns={columns} /> : <Empty>{t("reports.none")}</Empty>}</Card>
    </>
  );
}
