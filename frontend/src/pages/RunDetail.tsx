import { Download, GitCompare, XCircle } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { api, downloadUrl } from "../api/client";
import type { Comparison, Endpoint, Finding, FindingBrief, RunDetail as Detail } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ConfirmButton, Empty, ErrorNote, Loading, Metric, Note, PageHeader, SeverityBadge, StatusBadge, TagList, useLoad } from "../components/common";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { DataTable, type Column } from "../components/DataTable";
import { useI18n } from "../i18n";
import { formatDate, formatDuration } from "../lib/utils";

const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const endpointLabel = (e: Endpoint) => `${e.hostname || e.ip_address}:${e.port}`;

function endpointColumns(t: (key: never) => string): Column<Endpoint>[] {
  const tr = t as unknown as (k: string) => string;
  return [
    { key: "endpoint", header: "Endpoint", values: (e) => [e.hostname || e.ip_address], sort: endpointLabel, render: (e) => <span className="row-link">{endpointLabel(e)}</span> },
    { key: "tags", header: tr("col.tags"), values: (e) => e.tags ?? [], render: (e) => (e.tags?.length ? <TagList tags={e.tags} /> : "—") },
    { key: "grade", header: tr("run.grade"), values: (e) => [e.grade], render: (e) => e.grade },
    { key: "status", header: tr("col.status"), values: (e) => [e.compliance_status], render: (e) => e.compliance_status },
    { key: "tls", header: "TLS", values: (e) => e.tls_versions, sort: (e) => e.tls_versions.join(", "), render: (e) => e.tls_versions.join(", ") },
    { key: "cert", header: tr("run.certificate"), values: (e) => [String(e.certificate.subject ?? "")], sort: (e) => String(e.certificate.valid_until ?? ""),
      render: (e) => <span className="text-xs">{String(e.certificate.subject ?? "")}<br /><span className="text-muted">{String(e.certificate.valid_until ?? "")}</span></span> },
    { key: "errors", header: tr("run.errors"), values: (e) => (e.errors.length ? ["errors"] : e.untested_checks.length ? ["untested"] : []), sort: (e) => e.errors.length * 1000 + e.untested_checks.length,
      render: (e) => <>{e.errors.length ? <Badge tone="danger">{e.errors.length}</Badge> : "—"}{e.untested_checks.length > 0 && <Badge tone="warning" className="ml-1">{tr("run.notTested")}: {e.untested_checks.length}</Badge>}</> },
  ];
}

function findingColumns(t: (key: never) => string, label: (e: Endpoint) => string): Column<Finding>[] {
  const tr = t as unknown as (k: string) => string;
  void label;
  return [
    { key: "severity", header: tr("run.severity"), values: (f) => [f.severity], sort: (f) => SEVERITY_RANK[f.severity.toLowerCase()] ?? 0, render: (f) => <SeverityBadge severity={f.severity} /> },
    { key: "finding", header: tr("run.finding"), sort: (f) => f.title, values: (f) => [f.title],
      render: (f) => <><div className="font-medium">{f.title}</div><div className="text-xs text-muted">{f.evidence}</div><div className="mt-1 text-xs">{f.remediation}</div></> },
    { key: "category", header: "Category", values: (f) => [f.category], render: (f) => f.category || "—" },
    { key: "affected", header: tr("run.affected"), values: (f) => f.affected_endpoint_ids, sort: (f) => f.affected_endpoint_ids.length, render: (f) => <span className="text-xs">{f.affected_endpoint_ids.join(", ")}</span> },
  ];
}

function FindingList({ title, items, tone }: { title: string; items: FindingBrief[]; tone: "danger" | "success" | "warning" | "neutral" }) {
  return (
    <Card><CardHeader><CardTitle>{title} <Badge tone={tone}>{items.length}</Badge></CardTitle></CardHeader>
      {items.length ? <ul className="divide-y divide-hairline">{items.map((f) => <li key={f.finding_id} className="flex items-center justify-between gap-3 px-5 py-2.5 text-sm"><span>{f.title}<span className="block text-xs text-muted">{f.affected.join(", ")}</span></span><SeverityBadge severity={f.severity} /></li>)}</ul> : <p className="px-5 py-4 text-sm text-muted">—</p>}
    </Card>
  );
}

function ComparisonView({ runId }: { runId: string }) {
  const { t } = useI18n();
  const { data, error } = useLoad(() => api<Comparison>(`/scan-runs/${runId}/compare`), [runId]);
  if (error) return <ErrorNote error={error} />;
  if (!data) return null;
  return (
    <div className="space-y-4">
      {data.warnings.length > 0 && <Note tone="warning">{data.warnings.map((w) => t(`cmp.warn.${w}` as never)).join(" · ")}</Note>}
      <div className="grid gap-4 lg:grid-cols-2">
        <FindingList title={t("cmp.new")} items={data.new} tone="danger" />
        <FindingList title={t("cmp.fixed")} items={data.fixed} tone="success" />
        <FindingList title={t("cmp.persistent")} items={data.persistent} tone="warning" />
        <FindingList title={t("cmp.notRetested")} items={data.not_retested} tone="neutral" />
      </div>
      {data.endpoint_changes.length > 0 && <Card><CardHeader><CardTitle>{t("cmp.changes")}</CardTitle></CardHeader><CardContent><pre className="overflow-x-auto text-xs">{JSON.stringify(data.endpoint_changes, null, 2)}</pre></CardContent></Card>}
    </div>
  );
}

export default function RunDetail() {
  const { id = "" } = useParams();
  const { t, locale } = useI18n();
  const { user, atLeast } = useAuth();
  const [cmp, setCmp] = useState(false);
  const [error, setError] = useState<unknown>();
  const { data: run, error: loadError, reload } = useLoad(() => api<Detail>(`/scan-runs/${id}`), [id], 3000);
  if (loadError) return <ErrorNote error={loadError} />;
  if (!run) return <Loading />;
  const active = run.status === "queued" || run.status === "running";
  const s = run.summary;
  return (
    <>
      <PageHeader title={run.name} subtitle={`${formatDate(run.queued_at, locale)} · ${formatDuration(run.duration_seconds)}`} actions={
        <>
          <StatusBadge status={run.status} />
          {active && (run.initiated_by === user?.id || atLeast("OPERATOR")) && <ConfirmButton label={<><XCircle className="size-4" />{t("action.cancelScan")}</>} confirm={t("confirm.cancelScan")} onConfirm={async () => { try { await api(`/scan-runs/${id}/cancel`, { method: "POST" }); void reload(); } catch (e) { setError(e); } }} />}
          {atLeast("USER") && !active && <Button variant="outline" onClick={() => setCmp(!cmp)}><GitCompare />{t("cmp.title")}</Button>}
        </>
      } />
      <ErrorNote error={error} />
      {active && <Card className="mb-4"><CardContent className="text-sm">{t(`phase.${run.phase}` as never)}{run.progress ? ` — ${run.progress.hosts_done}/${run.progress.hosts_total} ${t("run.hosts")}` : ""}{run.cancel_requested ? ` — ${t("run.cancelling")}` : ""}</CardContent></Card>}
      {run.error && <ErrorNote error={new Error(run.error)} />}
      {run.status === "completed" && run.endpoints.length === 0 && <Note tone="info" className="mb-4">{t("run.noTls")}</Note>}
      {run.status === "partial" || run.skipped_hosts?.length ? <Note tone="warning" className="mb-4">{t("run.partial")} {run.skipped_hosts?.length ? `(${t("run.skipped")}: ${run.skipped_hosts.join(", ")})` : ""}</Note> : null}
      {s && (
        <div className="metrics">
          {([[t("run.endpoints"), s.total_endpoints, ""], [t("run.compliant"), s.compliant_endpoints, "green"], [t("run.nonCompliant"), s.non_compliant_endpoints, s.non_compliant_endpoints ? "red" : ""], [t("run.critical"), s.critical_findings, s.critical_findings ? "red" : ""], [t("run.grade"), s.overall_grade, ""], [t("run.errors"), s.endpoints_with_errors, s.endpoints_with_errors ? "amber" : ""], [t("run.notTested"), s.checks_not_tested, ""]] as [string, unknown, string][]).map(([l, v, tone]) => (
            <Metric key={l} label={l} value={String(v ?? "—")} tone={tone === "red" || tone === "green" || tone === "amber" ? tone : undefined} />
          ))}
        </div>
      )}
      {cmp && <div className="mb-6"><ComparisonView runId={id} /></div>}
      {run.reports.length > 0 && (
        <Card className="mb-6"><CardHeader><CardTitle>{t("nav.reports")}</CardTitle></CardHeader><CardContent className="flex flex-wrap gap-2">
          {run.reports.filter((r) => ["html", "md", "csv", "cbom", "findings_csv"].includes(r.format)).map((r) => <Button key={r.format} asChild variant="outline" size="sm"><a href={downloadUrl(id, r.format)}><Download />{r.format.toUpperCase()}</a></Button>)}
          {run.reports.some((r) => r.format === "html") && <Button asChild size="sm"><a href={downloadUrl(id, "html", true)} target="_blank" rel="noreferrer">{t("run.openHtml")}</a></Button>}
        </CardContent></Card>
      )}
      <Card className="mb-6"><CardHeader><CardTitle>{t("run.endpointsTitle")}</CardTitle></CardHeader>
        {run.endpoints.length ? <DataTable rows={run.endpoints} rowKey={(e) => e.endpoint_id} columns={endpointColumns(t as never)} /> : <Empty>—</Empty>}
      </Card>
      <Card><CardHeader><CardTitle>{t("run.findings")}</CardTitle></CardHeader>
        {run.findings.length ? <DataTable rows={run.findings} rowKey={(f) => f.finding_id} columns={findingColumns(t as never, endpointLabel)} /> : <Empty>—</Empty>}
      </Card>
    </>
  );
}
