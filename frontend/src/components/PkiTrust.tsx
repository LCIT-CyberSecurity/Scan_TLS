import { ShieldCheck } from "lucide-react";
import type { Endpoint, RunTrustStore, TrustClass } from "../api/types";
import { useI18n } from "../i18n";
import { DataTable, type Column } from "./DataTable";
import { Note } from "./common";
import { Badge } from "./ui/badge";
import { Card, CardHeader, CardTitle } from "./ui/card";

const TONE: Record<TrustClass, "success" | "primary" | "danger" | "neutral" | "warning"> = { PUBLIC_TRUSTED: "success", PRIVATE_TRUSTED: "primary", UNTRUSTED: "danger", NOT_TESTED: "neutral", ERROR: "warning" };
const label = (e: Endpoint) => `${e.hostname || e.ip_address}:${e.port}`;
const str = (v: unknown) => (v === null || v === undefined || v === "" ? "" : String(v));

function nameStatus(e: Endpoint): { text: string; tone: "success" | "danger" | "warning" | "neutral" } {
  const check = e.tls_checks?.find((c) => c.check_id === "hostname_san");
  if (check && (check.status === "PASS" || check.status === "FAIL")) return { text: check.status, tone: check.status === "PASS" ? "success" : "danger" };
  return { text: "", tone: "neutral" };
}

export function trustClass(e: Endpoint): TrustClass | null { return (e.certificate.trust_classification as TrustClass | null | undefined) ?? null; }

export function PkiTrust({ endpoints, stores }: { endpoints: Endpoint[]; stores: RunTrustStore[] }) {
  const { t } = useI18n();
  const tr = t as unknown as (k: string) => string;
  const rows = endpoints.filter((e) => trustClass(e));
  if (!rows.length) return null;
  const reasons = (e: Endpoint) => (e.certificate.trust_store_results ?? []).filter((r) => r.status !== "trusted" && r.validation_error).map((r) => `${r.store_name}: ${r.validation_error}`);
  const columns: Column<Endpoint>[] = [
    { key: "endpoint", header: "Endpoint", values: (e) => [label(e)], sort: label, render: label },
    { key: "trust", header: t("run.pkiTrust"), values: (e) => [trustClass(e) ?? "NOT_TESTED"], render: (e) => { const c = trustClass(e) ?? "NOT_TESTED"; return <Badge tone={TONE[c]}>{tr(`pki.${c}`)}</Badge>; } },
    { key: "by", header: t("run.pkiBy"), values: (e) => e.certificate.trusted_by ?? [], render: (e) => <span className="text-xs">{e.certificate.trusted_by?.join(", ") || "—"}</span> },
    { key: "anchor", header: t("run.pkiAnchor"), sort: (e) => str(e.certificate.trust_anchor), render: (e) => <span className="break-words text-xs">{str(e.certificate.trust_anchor) || "—"}</span> },
    { key: "reason", header: t("run.pkiReason"), render: (e) => <span className="text-xs">{trustClass(e) === "UNTRUSTED" || trustClass(e) === "ERROR" ? reasons(e).join(" · ") || "—" : "—"}</span> },
    { key: "name", header: t("run.pkiName"), values: (e) => [nameStatus(e).text || t("run.pkiNotTested")], render: (e) => { const s = nameStatus(e); return s.text ? <Badge tone={s.tone}>{s.text}</Badge> : <span className="text-xs text-muted">{t("run.pkiNotTested")}</span>; } },
    { key: "cert", header: t("run.pkiCert"), values: (e) => [str(e.certificate.status) || "—"], render: (e) => <span className="text-xs">{str(e.certificate.status) || "—"}{typeof e.certificate.remaining_days === "number" && ` (${e.certificate.remaining_days} d)`}</span> },
    { key: "revocation", header: t("run.pkiRevocation"), values: (e) => [str(e.certificate.revocation_status) || t("run.pkiNotTested")], render: (e) => <span className="text-xs">{str(e.certificate.revocation_status) || t("run.pkiNotTested")}</span> },
  ];
  return (
    <Card className="mb-6">
      <CardHeader><CardTitle><ShieldCheck className="mr-2 inline size-4 text-primary" aria-hidden />{t("run.pkiTitle")}</CardTitle></CardHeader>
      <div className="space-y-3 px-5 pb-3">
        <Note tone="info">{t("run.pkiHint")}</Note>
        {stores.length > 0 && (
          <div><div className="text-sm font-medium">{t("run.pkiStores")}</div>
            <ul className="mt-1 space-y-1 text-xs">{stores.map((s) => <li key={`${s.id}-${s.version}`}><strong>{s.name}</strong> v{s.version} <span className="font-mono text-muted" title={s.content_sha256}>SHA-256 {s.content_sha256.slice(0, 16)}…</span><span className="block text-muted">{s.anchors.join(" · ")}</span></li>)}</ul></div>
        )}
      </div>
      <DataTable rows={rows} rowKey={(e) => e.endpoint_id} columns={columns} />
    </Card>
  );
}
