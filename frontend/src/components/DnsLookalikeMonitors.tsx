import { useEffect, useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { Empty, ErrorNote } from "../components/common";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Field, Input, Select, Textarea } from "../components/ui/input";
import { Table, Td, Th } from "../components/ui/table";
import { useI18n } from "../i18n";

type Monitor = { id: string; domain: string; enabled: boolean; deleted: boolean; options: Record<string, unknown>; schedule: { kind: string; params: Record<string, unknown>; timezone: string } | null; history: { id: string; status: string; created_at: string; finished_at: string | null; error: string; observations: number; new: number; changed: number }[] };
type Observation = { domain: string; status: string; dns_status: string; ct_status: string; rdap_status: string; change?: string; score?: number; wildcard?: boolean; records?: Record<string, string[]>; note?: string };
const defaults: { authorized: boolean; enabled: boolean; tlds: string; exclusions: string; max_candidates: number; min_score: number; concurrency: number; timeout_seconds: number; ct_enabled: boolean; max_ct: number; notifications_enabled: boolean; schedule_kind: string; schedule_params: Record<string, string | number>; timezone: string } = { authorized: false, enabled: false, tlds: "com,net,org,io", exclusions: "", max_candidates: 50, min_score: 0, concurrency: 5, timeout_seconds: 3, ct_enabled: false, max_ct: 5, notifications_enabled: false, schedule_kind: "daily", schedule_params: { time: "03:00" }, timezone: "UTC" };

export function DnsLookalikeMonitors() {
  const { t } = useI18n();
  const { user } = useAuth();
  const [rows, setRows] = useState<Monitor[]>([]);
  const [form, setForm] = useState({ ...defaults, domain: "" });
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<Monitor | undefined>();
  const [resultSets, setResultSets] = useState<Record<string, Observation[]>>({});
  const load = async () => { if (user?.role !== "ADMIN") return; try { setRows(await api<Monitor[]>("/dns-lookalike-monitors")); } catch (e) { setError(e); } };
  useEffect(() => { void load(); }, [user?.role]);
  if (user?.role !== "ADMIN") return null;

  const payload = (monitor?: Monitor, enabled = form.enabled) => {
    const values = monitor?.options ?? form;
    return {
      domain: monitor?.domain ?? form.domain, authorized: true, enabled,
      tlds: String(values.tlds ?? "").split(/[\s,;]+/).filter(Boolean),
      exclusions: (Array.isArray(values.exclusions) ? values.exclusions : String(values.exclusions ?? "").split(/[\s,;]+/)).filter(Boolean),
      max_candidates: Number(values.max_candidates ?? 50), min_score: Number(values.min_score ?? 0), concurrency: Number(values.concurrency ?? 5), timeout_seconds: Number(values.timeout_seconds ?? 3),
      ct_enabled: Boolean(values.ct_enabled), max_ct: Number(values.max_ct ?? 5), notifications_enabled: Boolean(values.notifications_enabled),
      schedule_kind: String(values.schedule_kind ?? "daily"), schedule_params: values.schedule_params ?? { time: "03:00" }, timezone: String(values.timezone ?? "UTC"),
    };
  };
  async function create() { setBusy(true); setError(undefined); try { await api(editing ? `/dns-lookalike-monitors/${editing.id}` : "/dns-lookalike-monitors", { method: editing ? "PUT" : "POST", body: payload(undefined, form.enabled) }); setForm({ ...defaults, domain: "" }); setEditing(undefined); await load(); } catch (e) { setError(e); } finally { setBusy(false); } }
  async function setEnabled(row: Monitor, enabled: boolean) { setBusy(true); setError(undefined); try { await api(`/dns-lookalike-monitors/${row.id}`, { method: "PUT", body: payload(row, enabled) }); await load(); } catch (e) { setError(e); } finally { setBusy(false); } }
  async function run(row: Monitor) { setBusy(true); setError(undefined); try { await api(`/dns-lookalike-monitors/${row.id}/run`, { method: "POST" }); await load(); } catch (e) { setError(e); } finally { setBusy(false); } }
  async function remove(row: Monitor) { if (!window.confirm(t("confirm.delete"))) return; setBusy(true); setError(undefined); try { await api(`/dns-lookalike-monitors/${row.id}`, { method: "DELETE" }); await load(); } catch (e) { setError(e); } finally { setBusy(false); } }
  function edit(row: Monitor) { const o = row.options; setEditing(row); setForm({ ...defaults, authorized: true, enabled: row.enabled, domain: row.domain,
    tlds: Array.isArray(o.tlds) ? o.tlds.join(", ") : "", exclusions: Array.isArray(o.exclusions) ? o.exclusions.join("\n") : "",
    max_candidates: Number(o.max_candidates ?? 50), min_score: Number(o.min_score ?? 0), concurrency: Number(o.concurrency ?? 5), timeout_seconds: Number(o.timeout_seconds ?? 3),
    ct_enabled: Boolean(o.ct_enabled), max_ct: Number(o.max_ct ?? 5), notifications_enabled: Boolean(o.notifications_enabled),
    schedule_kind: String(o.schedule_kind ?? "daily"), schedule_params: (o.schedule_params as Record<string, string | number>) ?? { time: "03:00" }, timezone: String(o.timezone ?? "UTC") }); }

  return <div className="space-y-4">
    <ErrorNote error={error} />
    <Card className="space-y-4 p-4">
      <div><h3 className="font-semibold">{t("lookalike.title")}</h3><p className="mt-1 text-sm text-muted">{t("lookalike.offHint")}</p></div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("lookalike.domain")}><Input value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })} placeholder="example.org" /></Field>
        <Field label={t("lookalike.tlds")}><Input value={form.tlds} onChange={(e) => setForm({ ...form, tlds: e.target.value })} /></Field>
        <Field label={t("lookalike.exclusions")}><Textarea rows={2} value={form.exclusions} onChange={(e) => setForm({ ...form, exclusions: e.target.value })} /></Field>
        <Field label={t("lookalike.limits")}><div className="flex gap-2"><Input aria-label={t("lookalike.maxCandidates")} type="number" min={1} max={200} value={form.max_candidates} onChange={(e) => setForm({ ...form, max_candidates: Number(e.target.value) })} /><Input aria-label={t("lookalike.concurrency")} type="number" min={1} max={10} value={form.concurrency} onChange={(e) => setForm({ ...form, concurrency: Number(e.target.value) })} /></div></Field>
        <Field label={t("lookalike.threshold")}><Input type="number" min={0} max={1} step={0.05} value={form.min_score} onChange={(e) => setForm({ ...form, min_score: Number(e.target.value) })} /></Field>
        <Field label={t("lookalike.frequency")}><Select value={form.schedule_kind} onChange={(e) => setForm({ ...form, schedule_kind: e.target.value, schedule_params: e.target.value === "weekly" ? { time: "03:00", weekday: 0 } : e.target.value === "monthly" ? { time: "03:00", day: 1 } : { time: "03:00" } })}><option value="daily">{t("sched.daily")}</option><option value="weekly">{t("sched.weekly")}</option><option value="monthly">{t("sched.monthly")}</option></Select></Field>
      </div>
      <div className="flex flex-wrap gap-x-5 gap-y-2 text-sm">
        <label className="flex items-center gap-2"><input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />{t("lookalike.activateNow")}</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={form.ct_enabled} onChange={(e) => setForm({ ...form, ct_enabled: e.target.checked })} />{t("lookalike.ct")}</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={form.notifications_enabled} onChange={(e) => setForm({ ...form, notifications_enabled: e.target.checked })} />{t("lookalike.notifications")}</label>
      </div>
      <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={form.authorized} onChange={(e) => setForm({ ...form, authorized: e.target.checked })} />{t("lookalike.authorize")}</label>
      <div className="flex gap-2"><Button disabled={busy || !form.domain.trim() || !form.authorized} onClick={() => void create()}>{editing ? t("action.save") : t("lookalike.create")}</Button>{editing && <Button variant="outline" onClick={() => { setEditing(undefined); setForm({ ...defaults, domain: "" }); }}>{t("action.cancel")}</Button>}</div>
    </Card>
    <Card>{rows.length ? <Table><thead><tr><Th>{t("lookalike.domain")}</Th><Th>{t("col.status")}</Th><Th>{t("lookalike.history")}</Th><Th /></tr></thead><tbody>{rows.map((row) => <tr key={row.id}>
      <Td className="font-medium">{row.domain}<div className="text-xs font-normal text-muted">{row.schedule?.kind ?? t("lookalike.noSchedule")}</div></Td>
      <Td><Badge tone={row.enabled ? "success" : "neutral"}>{row.enabled ? t("lookalike.enabled") : t("lookalike.paused")}</Badge></Td>
      <Td>{row.history.length ? <details><summary className="cursor-pointer">{row.history.length} {t("lookalike.runs")}</summary><ul className="mt-2 space-y-2 text-xs">{row.history.map((h) => <li key={h.id}>{new Date(h.created_at).toLocaleString()} · {h.status} · {h.observations} · +{h.new} / ~{h.changed}{h.error ? ` · ${h.error}` : ""}
        <details className="mt-1" onToggle={(event) => { if (event.currentTarget.open && !resultSets[h.id]) void api<{ id: string; result?: { observations?: Observation[] } }[]>(`/dns-lookalike-monitors/${row.id}/results`).then((items) => { const result = items.find((item) => item.id === h.id)?.result; setResultSets((current) => ({ ...current, [h.id]: result?.observations ?? [] })); }).catch(setError); }}><summary className="cursor-pointer">{t("lookalike.showObservations")}</summary><ul className="mt-1 space-y-1">{resultSets[h.id]?.map((o) => <li key={o.domain}><strong>{o.domain}</strong> · DNS {o.dns_status} · CT {o.ct_status} · RDAP {o.rdap_status} · {o.change ?? o.status}{o.wildcard ? " · wildcard" : ""}{o.score !== undefined ? ` · ${o.score.toFixed(2)}` : ""}<div className="text-muted">{o.note ?? Object.entries(o.records ?? {}).map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ")}</div></li>)}</ul></details>
      </li>)}</ul></details> : <span className="text-muted">{t("lookalike.noHistory")}</span>}</Td>
      <Td><div className="flex justify-end gap-2"><Button size="sm" variant="outline" disabled={busy || !row.enabled} onClick={() => void run(row)}>{t("lookalike.run")}</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => edit(row)}>{t("action.edit")}</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => void setEnabled(row, !row.enabled)}>{row.enabled ? t("lookalike.pause") : t("lookalike.enable")}</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => void remove(row)}>{t("action.delete")}</Button></div></Td>
    </tr>)}</tbody></Table> : <Empty>{t("lookalike.empty")}</Empty>}</Card>
  </div>;
}
