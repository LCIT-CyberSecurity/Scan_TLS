import { Loader2, Radar } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import type { DdApplyItem, DdConfig, DdInventory, DdItem, DdJob, DdMethod, DdReport, DdResults, Group, SI } from "../api/types";
import { useI18n } from "../i18n";
import { CheckList, ErrorNote, Note, TagsInput, useLoad } from "./common";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";
import { Field, Input, Select, Textarea } from "./ui/input";

type Step = "config" | "run" | "results" | "review";
type Choice = { action: "add" | "enrich"; targetId?: string };
const PAGE = 100;
const ORDER = ["dns", "axfr", "dictionary", "ct", "reverse"];
const METHODS = ["dns", "axfr", "dictionary", "ct"] as const;
const INV_TONE: Record<DdInventory, "success" | "neutral" | "info" | "warning"> = { NEW: "success", EXISTING: "neutral", ENRICHABLE: "info", CHANGED: "warning", OUT_OF_SCOPE: "neutral" };
const STATUS_TONE: Record<string, "success" | "danger" | "warning" | "neutral" | "info"> = { done: "success", failed: "danger", partial: "warning", skipped: "neutral", running: "info", pending: "neutral" };

function Methods({ methods }: { methods: Record<string, DdMethod> }) {
  const { t } = useI18n();
  const tr = t as unknown as (k: string, v?: Record<string, string | number>) => string;
  return (
    <ul className="space-y-1 text-sm" aria-label={t("dd.methods")}>
      {Object.entries(methods).sort(([a], [b]) => ORDER.indexOf(a) - ORDER.indexOf(b)).map(([name, m]) => (
        <li key={name} className="flex flex-wrap items-center gap-2"><Badge tone={STATUS_TONE[m.status] ?? "neutral"}>{tr(`dd.m.status.${m.status}`)}</Badge><strong>{tr(`dd.m.${name}`)}</strong>
          {m.status !== "pending" && m.status !== "running" && <span className="text-muted">{m.found}</span>}{m.detail && <span className="text-xs text-muted">{m.detail}</span>}</li>
      ))}
    </ul>
  );
}

function Wizard({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const tr = t as unknown as (k: string, v?: Record<string, string | number>) => string;
  const config = useLoad(() => api<DdConfig>("/targets/discover-config"));
  const systems = useLoad(() => api<SI[]>("/information-systems"));
  const groups = useLoad(() => api<Group[]>("/target-groups"));
  const [step, setStep] = useState<Step>("config");
  const [error, setError] = useState<unknown>();
  // ---- configuration
  const [domain, setDomain] = useState("");
  const [mode, setMode] = useState<"fast" | "advanced">("fast");
  const [methods, setMethods] = useState<Set<string>>(new Set(METHODS));
  const [authorized, setAuthorized] = useState(false);
  const [dnsServer, setDnsServer] = useState("");
  const [axfrServers, setAxfrServers] = useState<string[]>([]);
  const [dictionary, setDictionary] = useState<"small" | "extended" | "custom">("small");
  const [customWords, setCustomWords] = useState("");
  const [reverse, setReverse] = useState("");
  const [timeout, setTimeout_] = useState(5);
  const [concurrency, setConcurrency] = useState(20);
  // ---- run
  const [job, setJob] = useState<DdJob>();
  // ---- results
  const [data, setData] = useState<DdResults>();
  const [filters, setFilters] = useState({ inventory: "", source: "", q: "" });
  const [offset, setOffset] = useState(0);
  const [selection, setSelection] = useState<Record<string, Choice>>({});
  // ---- review
  const [tags, setTags] = useState<string[]>([]);
  const [siIds, setSiIds] = useState<string[]>([]);
  const [groupMode, setGroupMode] = useState<"none" | "existing" | "new">("none");
  const [groupId, setGroupId] = useState("");
  const [groupName, setGroupName] = useState("");
  const [ports, setPorts] = useState("");
  const [confirmBusiness, setConfirmBusiness] = useState(false);
  const [plan, setPlan] = useState<DdReport>();
  const [report, setReport] = useState<DdReport>();
  const [busy, setBusy] = useState(false);
  const allowed = config.data?.allowed_servers ?? [];
  const advanced = mode === "advanced";
  const activeMethods = useMemo(() => METHODS.filter((m) => methods.has(m)).concat(advanced && methods.has("reverse") ? ["reverse" as never] : []), [methods, advanced]);

  const toggleMethod = (m: string) => setMethods((s) => { const n = new Set(s); if (n.has(m)) n.delete(m); else n.add(m); return n; });

  async function start() {
    setError(undefined);
    const body: Record<string, unknown> = { domain, authorized, mode, methods: activeMethods, timeout_seconds: timeout, concurrency };
    if (advanced) {
      if (dnsServer) body.dns_server = dnsServer;
      body.axfr_servers = axfrServers;
      body.dictionary = dictionary;
      if (dictionary === "custom") body.custom_words = customWords.split("\n").map((w) => w.trim()).filter(Boolean);
      if (methods.has("reverse")) body.reverse = reverse.split(/[\s,;]+/).filter(Boolean);
    }
    try { setJob(await api<DdJob>("/targets/discover", { method: "POST", body })); setStep("run"); } catch (e) { setError(e); }
  }

  // poll while queued / running (no artificial percentage: the bar only appears when a total is known)
  useEffect(() => {
    if (step !== "run" || !job || job.status === "done" || job.status === "failed") return;
    const timer = window.setTimeout(() => { api<DdJob>(`/targets/discover/${job.id}`).then(setJob).catch(setError); }, 1500);
    return () => window.clearTimeout(timer);
  }, [step, job]);
  useEffect(() => { if (step === "run" && job && (job.status === "done" || job.status === "failed")) { void loadResults(0, filters); setStep("results"); } /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [job?.status, step]);

  async function loadResults(newOffset: number, f = filters) {
    if (!job) return;
    try {
      setData(await api<DdResults>(`/targets/discover/${job.id}/results`, { params: { inventory: f.inventory, source: f.source, q: f.q, offset: String(newOffset), limit: String(PAGE) } }));
      setOffset(newOffset);
    } catch (e) { setError(e); }
  }
  const filterTimer = useRef<number | undefined>(undefined);
  const setFilter = (patch: Partial<typeof filters>) => {
    const next = { ...filters, ...patch };
    setFilters(next);
    window.clearTimeout(filterTimer.current);
    filterTimer.current = window.setTimeout(() => void loadResults(0, next), 250);
  };

  const choiceFor = (item: DdItem): Choice | undefined => {
    if (!item.in_scope) return undefined;
    if (item.inventory === "NEW") return { action: "add" };
    if (item.matches.length === 1) return { action: "enrich", targetId: item.matches[0].id };
    return undefined; // several targets: the user must choose one
  };
  const toggle = (item: DdItem, on: boolean) => setSelection((s) => { const n = { ...s }; const c = choiceFor(item); if (on && c) n[item.fqdn] = c; else delete n[item.fqdn]; return n; });
  const pickTarget = (item: DdItem, targetId: string) => setSelection((s) => { const n = { ...s }; if (targetId) n[item.fqdn] = { action: "enrich", targetId }; else delete n[item.fqdn]; return n; });
  async function selectWhere(inventory: DdInventory) {
    if (!job) return;
    const picked: Record<string, Choice> = { ...selection };
    for (let start = 0; ; start += 500) {
      const page = await api<DdResults>(`/targets/discover/${job.id}/results`, { params: { inventory, offset: String(start), limit: "500" } });
      for (const item of page.items) { const c = choiceFor(item); if (c && !item.wildcard && !item.notes.includes("ct_historical")) picked[item.fqdn] = c; }
      if (start + 500 >= page.total) break;
    }
    setSelection(picked);
  }

  const applyBody = (dry: boolean) => ({
    items: Object.entries(selection).map(([fqdn, c]) => ({ fqdn, action: c.action, target_id: c.targetId })),
    ports, tags, si_ids: siIds, dry_run: dry, confirm_business_changes: confirmBusiness,
    ...(groupMode === "existing" && groupId ? { group_id: groupId } : {}), ...(groupMode === "new" && groupName.trim() ? { group_name: groupName.trim() } : {}),
  });
  useEffect(() => {
    if (step !== "review" || !job || report) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      api<DdReport>(`/targets/discover/${job.id}/apply`, { method: "POST", body: applyBody(true) }).then((p) => { if (!cancelled) { setPlan(p); setError(undefined); } }).catch((e) => { if (!cancelled) { setPlan(undefined); setError(e); } });
    }, 300);
    return () => { cancelled = true; window.clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, selection, tags, siIds, groupMode, groupId, groupName, ports, confirmBusiness, report]);

  async function applyNow() {
    if (!job) return;
    setBusy(true);
    try { setReport(await api<DdReport>(`/targets/discover/${job.id}/apply`, { method: "POST", body: applyBody(false) })); setError(undefined); onDone(); } catch (e) { setError(e); } finally { setBusy(false); }
  }

  const selected = Object.keys(selection).length;
  const steps: [Step, string][] = [["config", "dd.step.config"], ["run", "dd.step.run"], ["results", "dd.step.results"], ["review", "dd.step.review"]];
  const failed = job?.status === "failed";

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={t("discover.title")} wide>
      <div className="space-y-4">
        <ol className="flex flex-wrap gap-2 text-xs" aria-label="steps">{steps.map(([s, key], i) => <li key={s} aria-current={s === step ? "step" : undefined}><Badge tone={s === step ? "primary" : "neutral"}>{i + 1}. {tr(key)}</Badge></li>)}</ol>
        <ErrorNote error={error} />

        {step === "config" && (
          <div className="space-y-4">
            <p className="text-sm text-muted">{t("dd.intro")}</p>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("discover.domain")}><Input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.org" /></Field>
              <Field label={t("dd.mode")} hint={mode === "fast" ? t("dd.mode.fastHint") : undefined}>
                <Select value={mode} onChange={(e) => setMode(e.target.value as "fast" | "advanced")}><option value="fast">{t("dd.mode.fast")}</option><option value="advanced">{t("dd.mode.advanced")}</option></Select></Field>
            </div>
            <fieldset className="space-y-1" aria-label={t("dd.methods")}>
              <legend className="mb-1 text-sm font-medium">{t("dd.methods")}</legend>
              {[...METHODS, ...(advanced ? ["reverse" as const] : [])].map((m) => (
                <label key={m} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={methods.has(m)} disabled={m === "ct" && config.data?.ct_enabled === false} onChange={() => toggleMethod(m)} />{tr(`dd.m.${m}`)}{m === "ct" && config.data?.ct_enabled === false && <span className="text-xs text-muted">{t("dd.ctOff")}</span>}</label>
              ))}
            </fieldset>
            {advanced && (
              <details open className="space-y-4 rounded-sm border border-hairline p-3"><summary className="cursor-pointer text-sm font-medium">{t("dd.options")}</summary>
                <div className="mt-3 space-y-4">
                  <Field label={t("dd.dnsServer")}>
                    <Select value={dnsServer} onChange={(e) => setDnsServer(e.target.value)}><option value="">{t("dd.dnsSystem")}</option>{allowed.map((a) => <option key={a} value={a}>{a}</option>)}</Select></Field>
                  {!allowed.length && <p className="text-xs text-muted">{t("dd.dnsNone")}</p>}
                  {allowed.length > 0 && methods.has("axfr") && <fieldset aria-label={t("dd.axfrServers")}><legend className="text-sm">{t("dd.axfrServers")}</legend>
                    {allowed.map((a) => <label key={a} className="mr-4 inline-flex items-center gap-2 text-sm"><input type="checkbox" checked={axfrServers.includes(a)} onChange={(e) => setAxfrServers((s) => e.target.checked ? [...s, a] : s.filter((x) => x !== a))} />{a}</label>)}</fieldset>}
                  {methods.has("dictionary") && <>
                    <Field label={t("dd.dictionary")}><Select value={dictionary} onChange={(e) => setDictionary(e.target.value as "small" | "extended" | "custom")}><option value="small">{t("dd.dict.small")}</option><option value="extended">{t("dd.dict.extended")}</option><option value="custom">{t("dd.dict.custom")}</option></Select></Field>
                    {dictionary === "custom" && <Field label={t("dd.customWords")}><Textarea rows={4} value={customWords} onChange={(e) => setCustomWords(e.target.value)} placeholder={"intranet\ngit\nvpn"} /></Field>}</>}
                  {methods.has("reverse") && <Field label={t("dd.reverse")}><Textarea rows={2} value={reverse} onChange={(e) => setReverse(e.target.value)} placeholder="192.0.2.0/28" /></Field>}
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field label={t("dd.timeout")}><Input type="number" min={1} max={30} value={timeout} onChange={(e) => setTimeout_(Number(e.target.value))} /></Field>
                    <Field label={t("dd.concurrency")}><Input type="number" min={1} max={50} value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value))} /></Field>
                  </div>
                </div></details>
            )}
            <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} /><span>{t("dd.authorize")}</span></label>
            <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>{t("action.cancel")}</Button>
              <Button disabled={!domain.trim() || !authorized || activeMethods.length === 0} onClick={() => void start()}><Radar />{t("dd.start")}</Button></div>
          </div>
        )}

        {step === "run" && job && (
          <div className="space-y-3" role="status" aria-live="polite">
            <p className="flex items-center gap-2 text-sm font-medium"><Loader2 className="size-4 animate-spin text-primary" />{job.status === "queued" ? t("dd.queued") : t("dd.running")} — {job.domain}</p>
            {job.progress?.methods && <Methods methods={job.progress.methods} />}
            {job.progress && <p className="text-xs text-muted">{[job.progress.names !== undefined && t("dd.names", { n: job.progress.names }), job.progress.queries !== undefined && t("dd.queries", { n: job.progress.queries })].filter(Boolean).join(" · ")}</p>}
            {job.progress?.total ? <progress className="w-full" max={job.progress.total} value={job.progress.done ?? 0} aria-label={t("dd.running")} /> : null}
            <div className="flex justify-end gap-2"><Button variant="outline" disabled={job.cancel_requested} onClick={() => void api(`/targets/discover/${job.id}/cancel`, { method: "POST" }).then(() => api<DdJob>(`/targets/discover/${job.id}`).then(setJob)).catch(setError)}>{t("dd.cancel")}</Button></div>
          </div>
        )}

        {step === "results" && job && (
          <div className="space-y-3">
            {failed && <Note tone="warning">{job.error || t("dd.failed")}</Note>}
            {data?.partial && <Note tone="warning">{t("dd.partialNote")}</Note>}
            {data?.security.map((s) => <Note key={s.address} tone="danger">{t("dd.secOpen")} ({s.server}, {s.address})</Note>)}
            {data && <Methods methods={data.methods} />}
            {data && data.nameservers.length > 0 && (
              <details><summary className="cursor-pointer text-sm">{t("dd.axfrServersTitle")}</summary>
                <ul className="mt-1 space-y-1 text-xs">{data.nameservers.map((n) => <li key={`${n.name}-${n.address}`}><Badge tone={n.status === "transferred" ? "danger" : "neutral"}>{tr(`dd.xfr.${n.status}`)}</Badge> {n.name} <span className="text-muted">{n.address}{n.records ? ` · ${n.records}` : ""}</span></li>)}</ul></details>
            )}
            {data && (
              <>
                <div className="flex flex-wrap items-end gap-3">
                  <Field label={t("dd.search")}><Input value={filters.q} onChange={(e) => setFilter({ q: e.target.value })} /></Field>
                  <Field label={t("dd.inventory")}><Select value={filters.inventory} onChange={(e) => setFilter({ inventory: e.target.value })}><option value="">{t("dd.all")}</option>{Object.entries(data.counts).map(([k, n]) => <option key={k} value={k}>{tr(`dd.inv.${k}`)} ({n})</option>)}</Select></Field>
                  <Field label={t("dd.source")}><Select value={filters.source} onChange={(e) => setFilter({ source: e.target.value })}><option value="">{t("dd.all")}</option>{Object.entries(data.sources).map(([k, n]) => <option key={k} value={k}>{k} ({n})</option>)}</Select></Field>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button size="sm" variant="outline" onClick={() => void selectWhere("NEW")}>{t("dd.selectNew")}</Button>
                  <Button size="sm" variant="outline" onClick={() => void selectWhere("ENRICHABLE")}>{t("dd.selectEnrich")}</Button>
                  <Button size="sm" variant="outline" onClick={() => setSelection({})}>{t("dd.selectNone")}</Button>
                  <span className="text-sm text-muted">{t("dd.selected", { n: selected })}</span>
                  <span className="ml-auto text-xs text-muted">{t("dd.of", { shown: Math.min(offset + PAGE, data.total), total: data.total })}</span>
                </div>
                <div className="table-scroll max-h-[22rem] overflow-y-auto"><table className="simple-table">
                  <thead><tr><th><span className="sr-only">{t("dd.select")}</span></th><th>{t("dd.fqdn")}</th><th>{t("dd.ip")}</th><th>{t("dd.type")}</th><th>{t("dd.source")}</th><th>{t("dd.inventory")}</th></tr></thead>
                  <tbody>{data.items.map((item) => (
                    <tr key={item.fqdn}>
                      <td>{item.ambiguous && item.in_scope ? (
                        <Select aria-label={`${t("dd.ambiguous")} ${item.fqdn}`} className="compact w-40" value={selection[item.fqdn]?.targetId ?? ""} onChange={(e) => pickTarget(item, e.target.value)}><option value="">{t("dd.choose")}</option>{item.matches.map((m) => <option key={m.id} value={m.id}>{m.ports || "—"}</option>)}</Select>
                      ) : <input type="checkbox" aria-label={item.fqdn} disabled={!item.in_scope || (item.inventory === "EXISTING" && false)} checked={!!selection[item.fqdn]} onChange={(e) => toggle(item, e.target.checked)} />}</td>
                      <td className="break-all font-medium">{item.fqdn}
                        <div className="flex flex-wrap gap-1">{item.wildcard && <Badge>{t("dd.wildcard")}</Badge>}{item.notes.includes("ct_historical") && <Badge tone="warning">{t("dd.historical")}</Badge>}{item.notes.includes("ptr_mismatch") && <Badge tone="warning">{t("dd.ptrMismatch")}</Badge>}</div>
                        {item.diff && item.diff.new_ips.length > 0 && <div className="text-xs font-normal text-muted">{t("dd.newIps", { ips: item.diff.new_ips.join(", ") })}</div>}
                        {item.diff && item.diff.missing_ips.length > 0 && <div className="text-xs font-normal text-warning">{t("dd.missingIps", { ips: item.diff.missing_ips.join(", ") })}</div>}</td>
                      <td className="break-all text-xs">{item.ips.slice(0, 3).join(", ")}{item.ips.length > 3 ? ` +${item.ips.length - 3}` : ""}{!item.ips.length && item.cnames.length ? `→ ${item.cnames[0]}` : ""}</td>
                      <td className="text-xs">{item.types.join(", ")}</td>
                      <td className="text-xs">{item.sources.join(", ")}</td>
                      <td><Badge tone={INV_TONE[item.inventory]}>{tr(`dd.inv.${item.inventory}`)}</Badge></td>
                    </tr>))}</tbody></table></div>
                <div className="flex justify-between"><div className="flex gap-2"><Button size="sm" variant="outline" disabled={offset === 0} onClick={() => void loadResults(Math.max(0, offset - PAGE))}>{t("dd.prev")}</Button><Button size="sm" variant="outline" disabled={offset + PAGE >= data.total} onClick={() => void loadResults(offset + PAGE)}>{t("dd.next")}</Button></div>
                  {data.truncated && <span className="text-xs text-muted">{t("dd.truncated")}</span>}</div>
              </>
            )}
            <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>{t("action.close")}</Button><Button disabled={selected === 0} onClick={() => { setPlan(undefined); setReport(undefined); setStep("review"); }}>{t("dd.continue")} ({selected})</Button></div>
          </div>
        )}

        {step === "review" && job && (
          <div className="space-y-4">
            {!report && (
              <>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label={t("col.tags")} hint={t("hint.commaSeparated")}><TagsInput value={tags} onChange={setTags} /></Field>
                  <Field label={t("dd.ports")}><Input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="443,8443" /></Field>
                  <Field label={t("dd.group")}>
                    <Select value={groupMode === "existing" ? groupId : groupMode} onChange={(e) => { const v = e.target.value; if (v === "none" || v === "new") { setGroupMode(v); setGroupId(""); } else { setGroupMode("existing"); setGroupId(v); } }}>
                      <option value="none">{t("dd.groupNone")}</option><option value="new">{t("dd.groupNew")}</option>{groups.data?.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}</Select></Field>
                  {groupMode === "new" && <Field label={t("dd.groupName")}><Input value={groupName} onChange={(e) => setGroupName(e.target.value)} /></Field>}
                </div>
                <Field label={t("col.si")}><CheckList items={(systems.data ?? []).map((s) => ({ id: s.id, label: (s.parent_id ? "↳ " : "") + s.name }))} selected={siIds} onChange={setSiIds} /></Field>
              </>
            )}
            {(report ?? plan) && (() => {
              const r = (report ?? plan) as DdReport;
              const pending = r.summary.business_changes_pending_confirmation;
              return (
                <div className="space-y-3" aria-label={t("dd.review")}>
                  {report ? <Note tone="success">{t("dd.done", { create: report.summary.create, reuse: report.summary.reuse, enrich: report.summary.enrich, skipped: report.summary.skipped })}</Note> : (
                    <ul className="list-disc pl-5 text-sm"><li>{t("dd.willCreate", { n: r.summary.create })}</li><li>{t("dd.willReuse", { n: r.summary.reuse })}</li><li>{t("dd.willEnrich", { n: r.summary.enrich })}</li>{r.summary.skipped > 0 && <li className="text-danger">{t("dd.willSkip", { n: r.summary.skipped })}</li>}</ul>)}
                  {!report && (pending > 0 || confirmBusiness) && <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={confirmBusiness} onChange={(e) => setConfirmBusiness(e.target.checked)} /><span>{t("dd.confirmBusiness", { n: r.items.filter((i) => i.business_changes && (i.business_changes.tags_added.length || i.business_changes.si_added.length || i.business_changes.group_added)).length })}</span></label>}
                  <div className="table-scroll max-h-60 overflow-y-auto"><table className="simple-table"><tbody>{r.items.map((i: DdApplyItem) => (
                    <tr key={i.fqdn}><td className="break-all">{i.fqdn}</td><td><Badge tone={i.outcome === "skip" ? "danger" : i.outcome === "create" ? "success" : "info"}>{i.outcome}</Badge></td>
                      <td className="text-xs text-muted">{i.outcome === "skip" ? tr(`dd.reason.${i.reason}`) : [i.dns?.new_ips.length ? t("dd.newIps", { ips: i.dns.new_ips.join(", ") }) : "", i.classification ? t("dd.classNotApplied") : ""].filter(Boolean).join(" · ")}</td></tr>))}</tbody></table></div>
                  <p className="text-xs text-muted">{t("dd.noScan")}</p>
                </div>
              );
            })()}
            <div className="flex justify-between gap-2">
              {!report ? <Button variant="outline" onClick={() => setStep("results")}>{t("dd.back")}</Button> : <span />}
              <div className="flex gap-2">
                <Button variant="outline" onClick={onClose}>{t("action.close")}</Button>
                {!report && <Button disabled={busy || !plan || plan.summary.create + plan.summary.reuse + plan.summary.enrich === 0} onClick={() => void applyNow()}>{t("dd.apply")}</Button>}
              </div>
            </div>
          </div>
        )}
      </div>
    </Dialog>
  );
}

export function DnsDiscoveryDialog(props: { onClose: () => void; onDone: () => void }) { return <Wizard {...props} />; }
