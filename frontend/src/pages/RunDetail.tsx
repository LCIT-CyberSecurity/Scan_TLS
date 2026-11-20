import { ArrowLeft, Download, GitCompare, Trash2, XCircle } from "lucide-react";
import { useState } from "react";
import { useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, downloadUrl } from "../api/client";
import type { Comparison, Endpoint, Finding, FindingBrief, RunDetail as Detail, ServiceObservation, QuicObservation } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ConfirmButton, Empty, ErrorNote, Loading, Metric, Note, PageHeader, SeverityBadge, StatusBadge, TagList, useLoad } from "../components/common";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { DataTable, type Column } from "../components/DataTable";
import { GroupedEndpoints } from "../components/GroupedEndpoints";
import { PkiTrust } from "../components/PkiTrust";
import { ScanProgress } from "../components/ScanProgress";
import { useI18n } from "../i18n";
import type { TlsCheckResult } from "../lib/tlsChecks";
import { formatDate, formatDuration } from "../lib/utils";

const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const endpointLabel = (e: Endpoint) => `${e.hostname || e.ip_address}:${e.port}`;

function endpointColumns(t: (key: never) => string): Column<Endpoint>[] {
  const tr = t as unknown as (k: string) => string;
  return [
    { key: "endpoint", header: "Endpoint", values: (e) => [e.hostname || e.ip_address], sort: endpointLabel, render: (e) => <span className="row-link">{endpointLabel(e)}</span> },
    { key: "tags", header: tr("col.tags"), values: (e) => e.tags ?? [], render: (e) => (e.tags?.length ? <TagList tags={e.tags} /> : "—") },
    { key: "grade", header: tr("run.grade"), values: (e) => [e.grade], render: (e) => e.grade },
    { key: "exposure", header: tr("exposure.state"), values: (e) => [e.exposure?.state ?? "unknown"], render: (e) => <span className="text-xs" title={[e.exposure?.source, e.exposure?.evidence_method, e.exposure?.justification].filter(Boolean).join(" · ")}>{tr(`exposure.${e.exposure?.state ?? "unknown"}`)}{e.exposure?.validated ? ` · ${tr("exposure.validated")}` : ""}</span> },
    { key: "status", header: tr("col.status"), values: (e) => [e.compliance_status], render: (e) => e.compliance_status },
    { key: "tls", header: "TLS", values: (e) => e.tls_versions, sort: (e) => e.tls_versions.join(", "), render: (e) => e.tls_versions.join(", ") },
    { key: "cert", header: tr("run.certificate"), values: (e) => [String(e.certificate.subject ?? "")], sort: (e) => String(e.certificate.valid_until ?? ""),
      render: (e) => <span className="text-xs">{String(e.certificate.subject ?? "")}<br /><span className="text-muted">{String(e.certificate.valid_until ?? "")}</span></span> },
  ];
}

type TlsCheckRow = { endpoint: string; check: TlsCheckResult };
const TLS_STATUS_TONE: Record<string, "success" | "danger" | "warning" | "neutral"> = { PASS: "success", FAIL: "danger", ERROR: "danger", INCONCLUSIVE: "warning", NOT_TESTED: "warning", NOT_APPLICABLE: "neutral" };

function tlsCheckColumns(t: (key: never) => string): Column<TlsCheckRow>[] {
  const tr = t as unknown as (k: string) => string;
  return [
    { key: "endpoint", header: "Endpoint", values: (r) => [r.endpoint], sort: (r) => r.endpoint, render: (r) => r.endpoint },
    { key: "check", header: tr("run.tlsCheck"), values: (r) => [tr(`tls.check.${r.check.check_id}`)], sort: (r) => r.check.check_id, render: (r) => tr(`tls.check.${r.check.check_id}`) },
    { key: "status", header: tr("col.status"), values: (r) => [r.check.status], sort: (r) => r.check.status, render: (r) => <Badge tone={TLS_STATUS_TONE[r.check.status] ?? "neutral"}>{r.check.status}</Badge> },
    { key: "result", header: tr("run.tlsResult"), values: (r) => [r.check.message], render: (r) => <span className="text-xs">{r.check.message}</span> },
  ];
}

function findingColumns(t: (key: never) => string, endpoints: Endpoint[]): Column<Finding>[] {
  const tr = t as unknown as (k: string) => string;
  const byId = new Map(endpoints.map((e) => [e.endpoint_id, e]));
  return [
    { key: "severity", header: tr("run.severity"), values: (f) => [f.severity], sort: (f) => SEVERITY_RANK[f.severity.toLowerCase()] ?? 0, render: (f) => <SeverityBadge severity={f.severity} /> },
    { key: "finding", header: tr("run.finding"), sort: (f) => f.title, values: (f) => [f.title],
      render: (f) => <><div className="font-medium">{f.title}</div><div className="text-xs text-muted">{f.evidence}</div><div className="mt-1 text-xs">{f.remediation}</div><ul className="mt-2 space-y-1 text-xs">{f.affected_endpoint_ids.map((id) => { const risk = f.contextual_risk_by_endpoint?.[id]; const endpoint = byId.get(id); return <li key={id} title={[risk?.reason, risk?.source, risk?.evidence_method, risk?.justification].filter(Boolean).join(" · ")}>{endpoint ? endpointLabel(endpoint) : id} · {tr("exposure.contextualRisk")}: {risk?.contextual_severity ?? tr("exposure.notEvaluated")}</li>; })}</ul></> },
    { key: "category", header: "Category", values: (f) => [f.category], render: (f) => f.category || "—" },
    { key: "affected", header: tr("run.affected"), values: (f) => f.affected_endpoint_ids.map((id) => { const e = byId.get(id); return e ? endpointLabel(e) : id; }), sort: (f) => f.affected_endpoint_ids.map((id) => { const e = byId.get(id); return e ? endpointLabel(e) : id; }).join(", "), render: (f) => (
      <span className="text-xs">
        {f.affected_endpoint_ids.map((id, i) => {
          const e = byId.get(id);
          // the name when known, the id otherwise; the tooltip gives both the FQDN and the IP
          return <span key={id}>{i > 0 && ", "}<span title={e ? `${e.hostname && e.hostname !== e.ip_address ? `${e.hostname}\n` : ""}${e.ip_address}:${e.port}` : id}>{e ? endpointLabel(e) : id}</span></span>;
        })}
      </span>
    ) },
  ];
}

function FindingList({ title, items, tone }: { title: string; items: FindingBrief[]; tone: "danger" | "success" | "warning" | "neutral" }) {
  return (
    <Card><CardHeader><CardTitle>{title} <Badge tone={tone}>{items.length}</Badge></CardTitle></CardHeader>
      {items.length ? <ul className="divide-y divide-hairline">{items.map((f) => <li key={f.finding_id} className="flex items-center justify-between gap-3 px-5 py-2.5 text-sm"><span>{f.title}<span className="block text-xs text-muted">{f.affected.join(", ")}</span></span><SeverityBadge severity={f.severity} /></li>)}</ul> : <p className="px-5 py-4 text-sm text-muted">—</p>}
    </Card>
  );
}

function ComparisonView({ runId, withRun }: { runId: string; withRun?: string }) {
  const { t } = useI18n();
  const { data, error } = useLoad(() => api<Comparison>(`/scan-runs/${runId}/compare`, { params: withRun ? { with_run: withRun } : undefined }), [runId, withRun]);
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
  const navigate = useNavigate();
  const location = useLocation();
  // Back to where the user came from (History, Reports with its filters, dashboard, map...); a page opened directly
  // (link, new tab) has no previous entry in the application, so it goes to the scan history instead of leaving it.
  const goBack = () => (location.key === "default" ? navigate("/scans?tab=history") : navigate(-1));
  const [byHost, setByHost] = useState(true);
  const [params] = useSearchParams();
  const withRun = params.get("compare") ?? undefined;   // set by the dashboard evolution card: compare with that scan instead of the previous one
  const [cmp, setCmp] = useState(!!withRun);
  const [error, setError] = useState<unknown>();
  const { data: run, error: loadError, reload } = useLoad(() => api<Detail>(`/scan-runs/${id}`), [id], 3000);
  if (loadError) return <ErrorNote error={loadError} />;
  if (!run) return <Loading />;
  const active = run.status === "queued" || run.status === "running";
  const s = run.summary;
  const tlsCheckRows = run.endpoints.flatMap((e) => (e.tls_checks ?? []).map((check) => ({ endpoint: endpointLabel(e), check })));
  return (
    <>
      <PageHeader title={run.name} subtitle={`${formatDate(run.queued_at, locale)} · ${formatDuration(run.duration_seconds)}`} actions={
        <>
          <Button variant="outline" onClick={goBack}><ArrowLeft />{t("action.back")}</Button>
          <StatusBadge status={run.status} />
          {active && (run.initiated_by === user?.id || atLeast("OPERATOR")) && <ConfirmButton label={<><XCircle className="size-4" />{t("action.cancelScan")}</>} confirm={t("confirm.cancelScan")} onConfirm={async () => { try { await api(`/scan-runs/${id}/cancel`, { method: "POST" }); void reload(); } catch (e) { setError(e); } }} />}
          {atLeast("USER") && !active && run.control_type !== "ipsec" && <Button variant="outline" onClick={() => setCmp(!cmp)}><GitCompare />{t("cmp.title")}</Button>}
          {atLeast("OPERATOR") && !active && <ConfirmButton label={<><Trash2 className="size-4" />{t("action.delete")}</>} confirm={t("confirm.deleteScan")} onConfirm={async () => { try { await api(`/scan-runs/${id}`, { method: "DELETE" }); navigate("/scans"); } catch (e) { setError(e); } }} />}
        </>
      } />
      <ErrorNote error={error} />
      {active && <ScanProgress run={run} />}
      {run.exclusions && run.exclusions.entries.length > 0 && (
        <details className="mb-4 rounded-sm border border-hairline p-3 text-sm"><summary className="cursor-pointer">{t("excl.run", { n: run.exclusions.entries.length })}{run.exclusions.removed_targets.length ? ` — ${t("excl.removed", { list: run.exclusions.removed_targets.join(", ") })}` : ""}</summary>
          <ul className="mt-2 space-y-1 text-xs">{run.exclusions.entries.map((e) => <li key={e.value}><code>{e.value}</code> <Badge>{t(`excl.scope.${e.scope}` as never)}</Badge></li>)}</ul>
          {run.exclusions.partial_targets.length > 0 && <p className="mt-2 text-xs text-muted">{t("excl.partial", { list: run.exclusions.partial_targets.join(", ") })}</p>}</details>
      )}
      {run.error && <ErrorNote error={new Error(run.error)} />}
      {run.status === "completed" && run.control_type === "tls" && run.endpoints.length === 0 && <Note tone="info" className="mb-4">{t("run.noTls")}</Note>}
      {run.status === "partial" || run.skipped_hosts?.length ? <Note tone="warning" className="mb-4">{t("run.partial")} {run.skipped_hosts?.length ? `(${t("run.skipped")}: ${run.skipped_hosts.join(", ")})` : ""}</Note> : null}
      {s && run.control_type !== "ipsec" && (
        <div className="metrics">
          {([[t("run.endpoints"), s.total_endpoints, ""], [t("run.compliant"), s.compliant_endpoints, "green"], [t("run.nonCompliant"), s.non_compliant_endpoints, s.non_compliant_endpoints ? "red" : ""], [t("run.critical"), s.critical_findings, s.critical_findings ? "red" : ""], [t("run.grade"), s.overall_grade, ""], [t("run.errors"), s.endpoints_with_errors, s.endpoints_with_errors ? "amber" : ""], [t("run.notTested"), s.checks_not_tested, ""]] as [string, unknown, string][]).map(([l, v, tone]) => (
            <Metric key={l} label={l} value={String(v ?? "—")} tone={tone === "red" || tone === "green" || tone === "amber" ? tone : undefined} />
          ))}
        </div>
      )}
      {cmp && run.control_type !== "ipsec" && <div className="mb-6"><ComparisonView runId={id} withRun={withRun} /></div>}
      {run.reports.length > 0 && (
        <Card className="mb-6"><CardHeader><CardTitle>{t("nav.reports")}</CardTitle></CardHeader><CardContent className="flex flex-wrap gap-2">
      {run.reports.filter((r) => ["html", "md", "csv", "cbom", "findings_csv", "contextual_risk_csv", "mail_security_csv", "service_csv", "ipsec_html", "ipsec_md", "ipsec_csv", "ssh_html", "ssh_md", "ssh_csv"].includes(r.format)).map((r) => <Button key={r.format} asChild variant="outline" size="sm"><a href={downloadUrl(id, r.format)}><Download />{r.format === "service_csv" ? "SERVICES CSV" : r.format === "mail_security_csv" ? "MAIL CSV" : r.format === "contextual_risk_csv" ? "CONTEXTUAL RISK CSV" : r.format.replaceAll("_", " ").toUpperCase()}</a></Button>)}
          {run.reports.filter((r) => ["html", "ipsec_html", "ssh_html"].includes(r.format)).map((r) => <Button key={`${r.format}-open`} asChild size="sm"><a href={downloadUrl(id, r.format, true)} target="_blank" rel="noreferrer">{t("run.openHtml")} · {r.format.replace("_html", "").toUpperCase()}</a></Button>)}
        </CardContent></Card>
      )}
      {run.control_type !== "ipsec" && <Card className="mb-6">
        <CardHeader><CardTitle>{t("run.endpointsTitle")}</CardTitle>
          <div className="segmented" role="group" aria-label={t("run.endpointsTitle")}>
            <button type="button" aria-pressed={byHost} className={byHost ? "active" : ""} onClick={() => setByHost(true)}>{t("run.byHost")}</button>
            <button type="button" aria-pressed={!byHost} className={!byHost ? "active" : ""} onClick={() => setByHost(false)}>{t("run.allEndpoints")}</button>
          </div>
        </CardHeader>
        {run.endpoints.length ? (byHost ? <GroupedEndpoints rows={run.endpoints} columns={endpointColumns(t as never)} /> : <DataTable rows={run.endpoints} rowKey={(e) => e.endpoint_id} columns={endpointColumns(t as never)} />) : <Empty>—</Empty>}
      </Card>}
      {run.control_type !== "ipsec" && <PkiTrust endpoints={run.endpoints} stores={run.trust_stores ?? []} />}
      {run.control_type !== "ipsec" && tlsCheckRows.length > 0 && (
        <Card className="mb-6"><CardHeader><CardTitle>{t("run.tlsChecks")}</CardTitle></CardHeader>
          <p className="px-5 pb-2 text-xs text-muted">{t("run.tlsChecksHint")}</p>
          <DataTable rows={tlsCheckRows} rowKey={(r) => `${r.endpoint}/${r.check.check_id}`} columns={tlsCheckColumns(t as never)} />
        </Card>
      )}
      {!!run.mail_security_results?.length && <Card className="mb-6">
        <CardHeader><CardTitle>{t("mail.results" as never)}</CardTitle></CardHeader>
        <CardContent><p className="mb-3 text-xs text-muted">{t("mail.limits" as never)}</p>
          {run.mail_security_results.map((domain) => <section key={domain.domain} className="mb-5 last:mb-0">
            <h3 className="mb-2 text-sm font-semibold">{domain.domain}</h3>
            {!!domain.smtp_starttls?.length && <p className="mb-2 text-xs text-muted">{t("mail.smtpStarttls" as never)}: {domain.smtp_starttls.map((item) => `${item.host}${item.port ? `:${item.port}` : ""} — ${t(`mail.smtpStatus.${item.status}` as never)}${item.tls_versions.length ? ` (${item.tls_versions.join(", ")})` : ""}`).join(" · ")}</p>}
            <DataTable rows={domain.checks} rowKey={(row) => `${row.check}-${row.details.selector ?? ""}`} columns={[
              { key: "check", header: t("mail.check" as never), values: (row) => [row.check], render: (row) => row.check.toUpperCase() },
              { key: "status", header: t("mail.verdict" as never), values: (row) => [row.status], render: (row) => <Badge tone={row.status === "compliant" ? "success" : row.status === "non_compliant" || row.status === "error" ? "danger" : row.status === "warning" ? "warning" : "neutral"}>{t(`mail.status.${row.status}` as never)}</Badge> },
              { key: "message", header: t("mail.observation" as never), values: (row) => [row.message], render: (row) => <span className="text-xs">{row.message}</span> },
              { key: "evidence", header: t("mail.evidence" as never), values: (row) => row.records, render: (row) => <code className="break-all text-xs">{row.records.join("; ") || "—"}</code> },
            ]} />
          </section>)}
        </CardContent>
      </Card>}
      {(run.control_type === "ipsec" || run.control_type === "multi") && <Card className="mb-6"><CardHeader><CardTitle>{t("ipsec.results" as never)}</CardTitle></CardHeader>
        <p className="px-5 pb-3 text-xs text-muted">{t("ipsec.notice" as never)}</p>
        {run.ipsec_observations?.length ? <DataTable rows={run.ipsec_observations} rowKey={(r) => `${r.target}:${r.port}:${r.ike_version}`} columns={[
          { key: "target", header: "Target", values: (r) => [r.target], render: (r) => r.target },
          { key: "port", header: "UDP", values: (r) => [String(r.port)], render: (r) => r.port },
          { key: "version", header: "IKE", values: (r) => [r.ike_version], render: (r) => r.ike_version || "—" },
          { key: "status", header: "Probe", values: (r) => [r.status], render: (r) => r.status },
          { key: "verdict", header: "Policy", values: (r) => [r.verdict], render: (r) => <Badge tone={r.verdict === "compliant" ? "success" : r.verdict === "non_compliant" ? "danger" : "warning"}>{r.verdict}</Badge> },
          { key: "proposal", header: "Observed proposal", values: (r) => [JSON.stringify(r.proposal)], render: (r) => <span className="text-xs">{Object.entries(r.proposal).map(([k, v]) => `${k}: ${v}`).join(" · ") || "Non déterminable"}</span> },
        ]} /> : <Empty>—</Empty>}
      </Card>}
      {!!run.ssh_observations?.length && <Card className="mb-6"><CardHeader><CardTitle>SSH audit</CardTitle></CardHeader>
        <p className="px-5 pb-3 text-xs text-muted">Unauthenticated protocol observations from ssh-audit; authentication and rate tests are not performed.</p>
        <DataTable rows={run.ssh_observations} rowKey={(r) => `${r.target}:${r.port}`} columns={[
          { key: "target", header: "Target", values: (r) => [r.target], render: (r) => r.target },
          { key: "port", header: "TCP", values: (r) => [String(r.port)], render: (r) => r.port },
          { key: "status", header: "Probe", values: (r) => [r.status], render: (r) => r.status },
          { key: "verdict", header: "Policy", values: (r) => [r.verdict], render: (r) => <Badge tone={r.verdict === "compliant" ? "success" : r.verdict === "non_compliant" ? "danger" : "warning"}>{r.verdict}</Badge> },
          { key: "banner", header: "Banner", values: (r) => [r.banner], render: (r) => <code className="text-xs">{r.banner || "—"}</code> },
          { key: "fingerprints", header: "Host key fingerprints", values: (r) => Object.values(r.fingerprints).map(String), render: (r) => <code className="break-all text-xs">{Object.entries(r.fingerprints).map(([key, value]) => `${key}: ${String(value)}`).join(" · ") || "—"}</code> },
          { key: "algorithms", header: "Observed algorithms", values: (r) => Object.values(r.algorithms).flat(), render: (r) => <span className="text-xs">{Object.entries(r.algorithms).flatMap(([k, v]) => v.map((x) => `${k}: ${x}`)).join(" · ") || "Indeterminate"}</span> },
        ]} />
      </Card>}
      {!!run.service_observations?.length && <Card className="mb-6"><CardHeader><CardTitle>{t("service.results" as never)}</CardTitle></CardHeader>
        <p className="px-5 pb-3 text-xs text-muted">{t("service.resultsHint" as never)}</p>
        <DataTable rows={run.service_observations} rowKey={(r: ServiceObservation) => `${r.target}:${r.port ?? "none"}`} columns={[
          { key: "target", header: "Target", values: (r) => [r.target, ...(r.scope_targets ?? [])], render: (r) => <span>{r.target || "—"}{!!r.scope_targets?.length && r.scope_targets.some((name) => name !== r.target) && <small className="ml-1 block text-muted">{r.scope_targets.filter((name) => name !== r.target).join(", ")}</small>}</span> },
          { key: "port", header: "TCP", values: (r) => [String(r.port ?? "")], render: (r) => r.port ?? "—" },
          { key: "service", header: t("service.name" as never), values: (r) => [r.service, r.product, r.version], render: (r) => <span>{r.service || "—"}{r.product && ` · ${r.product}`}{r.version && ` ${r.version}`}</span> },
          { key: "confidence", header: t("service.confidence" as never), values: (r) => [String(r.confidence)], render: (r) => `${Math.round(r.confidence * 100)}%` },
          { key: "status", header: t("col.status"), values: (r) => [r.status], render: (r) => <Badge tone={r.status === "observed" ? "success" : r.status === "probable" ? "warning" : "neutral"}>{r.status}</Badge> },
        ]} />
      </Card>}
      {!!run.quic_observations?.length && <Card className="mb-6"><CardHeader><CardTitle>{t("quic.title" as never)}</CardTitle></CardHeader>
        <p className="px-5 pb-3 text-xs text-muted">{t("quic.resultsHint" as never)}</p>
        <DataTable rows={run.quic_observations} rowKey={(r: QuicObservation) => `${r.target}:${r.port ?? "none"}`} columns={[
          { key: "target", header: "Target", values: (r) => [r.target], render: (r) => r.target || "—" },
          { key: "port", header: "UDP", values: (r) => [String(r.port ?? "")], render: (r) => r.port ?? "—" },
          { key: "status", header: t("col.status"), values: (r) => [r.status], render: (r) => <Badge tone={r.status === "observed" ? "success" : "warning"}>{r.status}</Badge> },
          { key: "version", header: t("quic.version" as never), values: (r) => [r.quic_version ?? "", r.tls_version ?? ""], render: (r) => <span>{r.quic_version ?? "—"}{r.tls_version ? ` · ${r.tls_version}` : ""}</span> },
          { key: "alpn", header: "ALPN / HTTP/3", values: (r) => [r.alpn ?? "", r.http3_status ?? ""], render: (r) => <span>{r.alpn ?? "—"}{r.http3_status ? ` · ${r.http3_status}` : ""}</span> },
          { key: "cipher", header: t("quic.cipher" as never), values: (r) => [r.cipher_suite ?? ""], render: (r) => <code className="text-xs">{r.cipher_suite ?? "—"}</code> },
          { key: "policy", header: t("quic.policy" as never), values: (r) => (r.policy_evaluations ?? []).map((p) => p.policy), render: (r) => <span className="text-xs">{(r.policy_evaluations ?? []).map((p) => `${p.policy}: ${p.checks.map((c) => `${c.control}=${c.status}`).join(", ")}`).join(" · ") || "—"}</span> },
          { key: "observation", header: t("run.tlsCheck"), values: (r) => [r.reason ?? "", r.certificate?.sha256_fingerprint ?? ""], render: (r) => <span className="break-all text-xs">{r.reason ?? r.certificate?.sha256_fingerprint ?? "—"}</span> },
        ]} />
      </Card>}
      {run.control_type !== "ipsec" && <Card><CardHeader><CardTitle>{t("run.findings")}</CardTitle></CardHeader>
        {run.findings.length ? <DataTable rows={run.findings} rowKey={(f) => f.finding_id} columns={findingColumns(t as never, run.endpoints)} /> : <Empty>—</Empty>}
      </Card>}
    </>
  );
}
