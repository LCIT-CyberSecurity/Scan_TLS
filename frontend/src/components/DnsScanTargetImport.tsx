import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { DdReport, DdResults, DdSummary, Target } from "../api/types";
import { useI18n } from "../i18n";
import { ErrorNote, Note, useLoad } from "./common";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { Field, Input, Select } from "./ui/input";

const PAGE = 100;
const MAX_IMPORT = 500;

/** Imports DNS results into Targets only after preview and explicit confirmation. */
export function DnsScanTargetImport({ onImported }: { onImported: (targets: Target[]) => void }) {
  const { t } = useI18n();
  const translate = t as unknown as (key: string, values?: Record<string, string | number>) => string;
  const { data: discoveries, error: discoveryError } = useLoad(() => api<DdSummary[]>("/targets/discover"), []);
  const completed = useMemo(() => (discoveries ?? []).filter((d) => d.status === "done"), [discoveries]);
  const [discoveryId, setDiscoveryId] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string[]>([]);
  const [ports, setPorts] = useState("443");
  const [preview, setPreview] = useState<DdReport>();
  const [applied, setApplied] = useState<DdReport>();
  const [error, setError] = useState<unknown>();
  const [resultsError, setResultsError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [data, setData] = useState<DdResults>();
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!discoveryId) { setData(undefined); setLoading(false); return; }
    let active = true;
    setData(undefined); setLoading(true); setResultsError(undefined);
    api<DdResults>(`/targets/discover/${discoveryId}/results`, { params: { offset: String(offset), limit: String(PAGE) } })
      .then((result) => { if (active) setData(result); })
      .catch((reason: unknown) => { if (active) setResultsError(reason); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [discoveryId, offset]);
  useEffect(() => { setOffset(0); setSelected([]); setPreview(undefined); setApplied(undefined); setError(undefined); setData(undefined); }, [discoveryId]);

  const eligible = (item: DdResults["items"][number]) => item.in_scope && item.inventory === "NEW" && !item.wildcard && !item.notes.includes("ct_historical");
  const body = (dryRun: boolean) => ({ items: selected.map((fqdn) => ({ fqdn, action: "add" as const })), ports, discovery_tag: false, dry_run: dryRun, on_conflict: "skip" as const });

  async function selectAllMissing() {
    if (!discoveryId || !data || data.counts.NEW > MAX_IMPORT) return;
    setBusy(true); setError(undefined);
    try {
      const first = await api<DdResults>(`/targets/discover/${discoveryId}/results`, { params: { inventory: "NEW", offset: "0", limit: "500" } });
      const names = first.items.filter(eligible).map((item) => item.fqdn);
      for (let start = 500; start < first.total; start += 500) {
        const page = await api<DdResults>(`/targets/discover/${discoveryId}/results`, { params: { inventory: "NEW", offset: String(start), limit: "500" } });
        names.push(...page.items.filter(eligible).map((item) => item.fqdn));
      }
      setSelected(names.slice(0, MAX_IMPORT)); setPreview(undefined); setApplied(undefined);
    } catch (e) { setError(e); }
    finally { setBusy(false); }
  }

  async function showPreview() {
    if (!discoveryId || !selected.length) return;
    setBusy(true); setError(undefined); setApplied(undefined);
    try { setPreview(await api<DdReport>(`/targets/discover/${discoveryId}/apply`, { method: "POST", body: body(true) })); }
    catch (e) { setError(e); }
    finally { setBusy(false); }
  }

  async function confirmImport() {
    if (!discoveryId || !preview) return;
    setBusy(true); setError(undefined);
    try {
      const report = await api<DdReport>(`/targets/discover/${discoveryId}/apply`, { method: "POST", body: body(false) });
      const targets: Target[] = [...new Map(report.items.filter((item) => item.target_id).map((item) => [item.target_id!, {
        id: item.target_id!, name: "", value: item.fqdn, kind: "fqdn", ports, description: "DNS discovery", owner_id: null, tags: [], si_ids: [],
      }])).values()];
      onImported(targets);
      setApplied(report); setPreview(undefined);
    } catch (e) { setError(e); }
    finally { setBusy(false); }
  }

  return <Card className="space-y-3 p-3">
    <div><h3 className="text-sm font-medium">{t("scan.dnsImportTitle" as never)}</h3><p className="mt-1 text-xs text-muted">{t("scan.dnsImportHint" as never)}</p></div>
    <ErrorNote error={discoveryError ?? resultsError ?? error} />
    {!completed.length ? <p className="text-sm text-muted">{t("scan.dnsImportEmpty" as never)}</p> : <>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label={t("scan.dnsDiscovery" as never)}><Select value={discoveryId} onChange={(e) => { setData(undefined); setDiscoveryId(e.target.value); }}>
          <option value="">{t("scan.dnsChoose" as never)}</option>{completed.map((d) => <option key={d.id} value={d.id}>{d.domain} · {new Date(d.created_at).toLocaleDateString()}</option>)}
        </Select></Field>
        <Field label={t("target.ports" as never)}><Input value={ports} onChange={(e) => { setPorts(e.target.value); setPreview(undefined); setApplied(undefined); }} placeholder="443,8443" /></Field>
      </div>
      {data && <>
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
          <span>{t("scan.dnsCounts" as never, { total: data.total, selected: selected.length })}</span>
          <Button size="sm" variant="outline" disabled={busy || data.counts.NEW === 0 || data.counts.NEW > MAX_IMPORT} onClick={() => void selectAllMissing()}>{t("scan.dnsSelectMissing" as never)}</Button>
        </div>
        {data.counts.NEW > MAX_IMPORT && <p className="text-xs text-muted">{t("scan.dnsLimit" as never, { limit: MAX_IMPORT })}</p>}
        <div className="max-h-48 space-y-1 overflow-auto rounded border border-hairline p-2">
          {data.items.map((item) => <label key={item.fqdn} className="flex items-start gap-2 text-sm">
            <input type="checkbox" disabled={!eligible(item) || busy || (!selected.includes(item.fqdn) && selected.length >= MAX_IMPORT)} checked={selected.includes(item.fqdn)} onChange={(e) => {
              setSelected((current) => e.target.checked ? [...current, item.fqdn] : current.filter((value) => value !== item.fqdn));
              setPreview(undefined); setApplied(undefined);
            }} />
            <span className="min-w-0 flex-1"><span className="break-all font-medium">{item.fqdn}</span><span className="ml-2 text-xs text-muted">{item.ips.join(", ") || "—"}</span></span>
            <Badge tone={item.inventory === "NEW" ? "success" : "neutral"}>{translate(`dd.inv.${item.inventory}`)}</Badge>
          </label>)}
          {!data.items.length && <p className="text-sm text-muted">{t("scan.dnsNoEndpoints" as never)}</p>}
        </div>
        <div className="flex justify-between gap-2">
          <div className="flex gap-2"><Button size="sm" variant="outline" disabled={offset === 0 || busy} onClick={() => setOffset(Math.max(0, offset - PAGE))}>{t("dd.prev" as never)}</Button><Button size="sm" variant="outline" disabled={offset + PAGE >= data.total || busy} onClick={() => setOffset(offset + PAGE)}>{t("dd.next" as never)}</Button></div>
          <Button size="sm" disabled={!selected.length || busy || !ports.trim()} onClick={() => void showPreview()}>{t("scan.dnsPreview" as never)} ({selected.length})</Button>
        </div>
      </>}
      {loading && <p role="status" className="text-xs text-muted">{t("state.loading" as never)}</p>}
      {preview && <div className="space-y-2 rounded border border-hairline p-3" aria-label={t("scan.dnsPreview" as never)}>
        <p className="text-sm font-medium">{t("scan.dnsPreviewSummary" as never, { create: preview.summary.create, reuse: preview.summary.reuse, skipped: preview.summary.skipped })}</p>
        <ul className="max-h-32 space-y-1 overflow-auto text-xs">{preview.items.map((item) => <li key={item.fqdn} className="flex justify-between gap-2"><span className="break-all">{item.fqdn}</span><Badge tone={item.outcome === "skip" ? "warning" : "success"}>{item.outcome === "skip" ? item.reason : item.outcome}</Badge></li>)}</ul>
        <Note>{t("scan.dnsImportConfirmHint" as never)}</Note>
        <div className="flex justify-end"><Button size="sm" disabled={busy || preview.summary.create + preview.summary.reuse === 0} onClick={() => void confirmImport()}>{t("scan.dnsConfirmImport" as never)}</Button></div>
      </div>}
      {applied && <Note tone="success">{t("scan.dnsImported" as never, { count: applied.items.filter((item) => !!item.target_id).length })}</Note>}
    </>}
  </Card>;
}
