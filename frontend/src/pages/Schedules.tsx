import { Pencil, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Definition, Group, Schedule, Target } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ConfirmButton, Empty, ErrorNote, PageHeader, StatusBadge, useLoad } from "../components/common";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Dialog } from "../components/ui/dialog";
import { Field, Input, Select } from "../components/ui/input";
import { Table, Td, Th } from "../components/ui/table";
import { useI18n } from "../i18n";
import { formatDate, formatDuration } from "../lib/utils";

const TZ = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";

function ScheduleDialog({ defs, allowDns, schedule, onClose, onSaved }: { defs: Definition[]; allowDns: boolean; schedule?: Schedule; onClose: () => void; onSaved: () => void }) {
  const { t } = useI18n();
  const options = schedule?.task_config?.options ?? {};
  const reverseAddresses = options.reverse_addresses ?? options.reverse ?? [];
  const [definition, setDefinition] = useState(schedule?.definition_id ?? defs[0]?.id ?? "");
  const [taskType, setTaskType] = useState<"tls" | "dns_discovery">(schedule?.task_type ?? "tls");
  const [domain, setDomain] = useState(schedule?.task_config?.domain ?? "");
  const [authorized, setAuthorized] = useState(false);
  const [mode, setMode] = useState<"fast" | "advanced">((options.mode as "fast" | "advanced") ?? "fast");
  const [methods, setMethods] = useState<string[]>((options.methods as string[]) ?? ["dns", "axfr"]);
  const [dnsServer, setDnsServer] = useState((options.dns_server as string) ?? "");
  const [axfrServers, setAxfrServers] = useState(((options.axfr_servers as string[]) ?? []).join(", "));
  const [dictionary, setDictionary] = useState((options.dictionary as string) ?? "small");
  const [customWords, setCustomWords] = useState(((options.custom_words as string[]) ?? []).join(", "));
  const [reverse, setReverse] = useState((reverseAddresses as string[]).join(", "));
  const [timeout, setTimeout] = useState((options.timeout_seconds as number) ?? 5);
  const [concurrency, setConcurrency] = useState((options.concurrency as number) ?? 20);
  const [duration, setDuration] = useState((options.max_duration_seconds as number) ?? 300);
  const [kind, setKind] = useState(schedule?.kind ?? "daily");
  const [time, setTime] = useState((schedule?.params.time as string) ?? "03:00");
  const [weekday, setWeekday] = useState((schedule?.params.weekday as number) ?? 0);
  const [day, setDay] = useState((schedule?.params.day as number) ?? 1);
  const [at, setAt] = useState((schedule?.params.at as string)?.slice(0, 16) ?? "");
  const [expr, setExpr] = useState((schedule?.params.expr as string) ?? "0 3 * * 1");
  const [active, setActive] = useState(schedule?.active ?? true);
  const [error, setError] = useState<unknown>();
  const params = kind === "once" ? { at } : kind === "daily" ? { time } : kind === "weekly" ? { time, weekday } : kind === "monthly" ? { time, day } : { expr };
  function toggleMethod(method: string) { setMethods((current) => current.includes(method) ? current.filter((x) => x !== method) : [...current, method]); }
  const dnsOptions = { mode, methods, ...(dnsServer.trim() ? { dns_server: dnsServer.trim() } : {}),
    axfr_servers: axfrServers.split(/[\s,;]+/).filter(Boolean), dictionary,
    custom_words: customWords.split(/[\s,;]+/).filter(Boolean), reverse: reverse.split(/[\s,;]+/).filter(Boolean),
    timeout_seconds: timeout, concurrency, max_duration_seconds: duration };
  async function save() {
    const body = taskType === "tls"
      ? { task_type: "tls", definition_id: definition, kind, params, timezone: schedule?.timezone ?? TZ, active }
      : { task_type: "dns_discovery", domain, authorized, dns_options: dnsOptions, kind, params, timezone: schedule?.timezone ?? TZ, active };
    try { await api(schedule ? `/schedules/${schedule.id}` : "/schedules", { method: schedule ? "PUT" : "POST", body }); onSaved(); onClose(); } catch (e) { setError(e); }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={schedule ? t("sched.edit") : t("sched.new")}>
      <div className="space-y-4">
        {allowDns ? <Field label={t("sched.taskType")}><Select value={taskType} onChange={(e) => setTaskType(e.target.value as "tls" | "dns_discovery")}><option value="tls">{t("sched.task.tls")}</option><option value="dns_discovery">{t("sched.task.dns")}</option></Select></Field> : <p className="text-sm font-medium">{t("sched.task.tls")}</p>}
        {taskType === "tls" ? <Field label={t("sched.definition")}><Select value={definition} onChange={(e) => setDefinition(e.target.value)}>{defs.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</Select></Field> : <>
          <Field label={t("sched.domain")}><Input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.org" /></Field>
          <Field label={t("sched.mode")}><Select value={mode} onChange={(e) => { setMode(e.target.value as "fast" | "advanced"); if (e.target.value === "fast") setMethods((current) => current.filter((m) => m !== "reverse")); }}><option value="fast">{t("dd.mode.fast")}</option><option value="advanced">{t("dd.mode.advanced")}</option></Select></Field>
          <fieldset className="space-y-2"><legend className="text-sm font-medium">{t("dd.methods")}</legend>{["dns", "axfr", "dictionary", "ct", ...(mode === "advanced" ? ["reverse"] : [])].map((m) => <label key={m} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={methods.includes(m)} onChange={() => toggleMethod(m)} />{t(`dd.m.${m}` as never)}</label>)}</fieldset>
          {mode === "advanced" && <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t("dd.dnsServer")}><Input value={dnsServer} onChange={(e) => setDnsServer(e.target.value)} placeholder="10.0.0.53:53" /></Field>
            <Field label={t("dd.axfrServers")}><Input value={axfrServers} onChange={(e) => setAxfrServers(e.target.value)} /></Field>
            <Field label={t("dd.dictionary")}><Select value={dictionary} onChange={(e) => setDictionary(e.target.value)}><option value="small">{t("dd.dict.small")}</option><option value="extended">{t("dd.dict.extended")}</option><option value="custom">{t("dd.dict.custom")}</option></Select></Field>
            {dictionary === "custom" && <Field label={t("dd.customWords")}><Input value={customWords} onChange={(e) => setCustomWords(e.target.value)} /></Field>}
            <Field label={t("dd.reverse")}><Input value={reverse} onChange={(e) => setReverse(e.target.value)} placeholder="192.0.2.0/28" /></Field>
            <Field label={t("dd.timeout")}><Input type="number" min={1} max={30} value={timeout} onChange={(e) => setTimeout(Number(e.target.value))} /></Field>
            <Field label={t("dd.concurrency")}><Input type="number" min={1} max={50} value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value))} /></Field>
            <Field label={t("sched.duration")}><Input type="number" min={30} max={900} value={duration} onChange={(e) => setDuration(Number(e.target.value))} /></Field>
          </div>}
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} /><span>{t("sched.authorized")}</span></label>
        </>}
        <Field label={t("sched.frequency")}><Select value={kind} onChange={(e) => setKind(e.target.value)}>{["once", "daily", "weekly", "monthly", "cron"].map((k) => <option key={k} value={k}>{t(`sched.${k}` as never)}</option>)}</Select></Field>
        {kind === "once" && <Field label={t("sched.at")}><Input type="datetime-local" value={at} onChange={(e) => setAt(e.target.value)} /></Field>}
        {["daily", "weekly", "monthly"].includes(kind) && <Field label={t("sched.time")}><Input type="time" value={time} onChange={(e) => setTime(e.target.value)} /></Field>}
        {kind === "weekly" && <Field label={t("sched.weekday")}><Select value={weekday} onChange={(e) => setWeekday(Number(e.target.value))}>{[0, 1, 2, 3, 4, 5, 6].map((d) => <option key={d} value={d}>{new Date(2024, 0, 1 + d).toLocaleDateString(undefined, { weekday: "long" })}</option>)}</Select></Field>}
        {kind === "monthly" && <Field label={t("sched.day")}><Input type="number" min={1} max={28} value={day} onChange={(e) => setDay(Number(e.target.value))} /></Field>}
        {kind === "cron" && <Field label={t("sched.cron")} hint={t("sched.cronHint")}><Input value={expr} onChange={(e) => setExpr(e.target.value)} /></Field>}
        <p className="text-xs text-muted">{t("sched.timezone")}: {schedule?.timezone ?? TZ}</p>
        {schedule && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} />{t("sched.active")}</label>}
        <ErrorNote error={error} />
        <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>{t("action.cancel")}</Button><Button disabled={taskType === "tls" ? !definition : !authorized || !domain.trim() || !methods.length} onClick={() => void save()}>{t("action.save")}</Button></div>
      </div>
    </Dialog>
  );
}

export default function Schedules() {
  const { t, locale } = useI18n();
  const { user, atLeast } = useAuth();
  const { data, reload, error } = useLoad(() => api<Schedule[]>("/schedules"), [], 10000);
  const { data: defs } = useLoad(() => api<Definition[]>("/scan-definitions"));
  const { data: targets } = useLoad(() => api<Target[]>("/targets"));
  const { data: groups } = useLoad(() => api<Group[]>("/target-groups"));
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Schedule | null>(null);
  const [detail, setDetail] = useState<Schedule | null>(null);
  const [err, setErr] = useState<unknown>();
  // The task opens its scan definition (frequency, time zone and activation stay here); its targets and groups open their
  // record. A DNS discovery is configured in the schedule itself, so it has no other screen to open.
  const task = (s: Schedule) => {
    if (s.task_type === "dns_discovery") return `${t("sched.task.dns")} · ${s.task_config?.domain ?? "—"}`;
    const definition = defs?.find((d) => d.id === s.definition_id);
    if (!definition) return <>{s.definition_id?.slice(0, 8) ?? "—"} <span className="text-xs font-normal text-muted">({t("sched.definitionMissing")})</span></>;
    const refs = [
      ...(definition.target_ids ?? []).map((id) => ({ key: `t-${id}`, to: `/targets?target=${id}`, label: targets?.find((x) => x.id === id)?.name || targets?.find((x) => x.id === id)?.value })),
      ...(definition.group_ids ?? []).map((id) => ({ key: `g-${id}`, to: `/targets?group=${id}`, label: groups?.find((g) => g.id === id)?.name && `${t("sched.group")} ${groups?.find((g) => g.id === id)?.name}` })),
    ].filter((ref) => ref.label);
    return <>
      <Link className="ref-link" to={`/scans?tab=scans&definition=${definition.id}`}>{definition.name}</Link>
      {refs.length > 0 && <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs font-normal" aria-label={t("def.targets")}>
        {refs.slice(0, 5).map((ref) => <Link key={ref.key} className="ref-link" to={ref.to}>{ref.label}</Link>)}
        {refs.length > 5 && <Link className="ref-link" to={`/scans?tab=scans&definition=${definition.id}`}>{t("sched.moreTargets", { n: refs.length - 5 })}</Link>}
      </div>}
    </>;
  };
  return (
    <>
      <PageHeader title={t("nav.schedules")} subtitle={atLeast("OPERATOR") ? t("sched.allSubtitle") : t("sched.mineSubtitle")} actions={<Button onClick={() => setOpen(true)} disabled={!defs || (!defs.length && !atLeast("OPERATOR"))}><Plus />{t("sched.new")}</Button>} />
      <ErrorNote error={error ?? err} />
      <Card>{data?.length ? (
        <Table><thead><tr><Th>{t("sched.taskType")}</Th><Th>{t("sched.frequency")}</Th><Th>{t("sched.next")}</Th><Th>{t("sched.last")}</Th><Th>{t("col.status")}</Th><Th /></tr></thead>
          <tbody>{data.map((s) => (
            <tr key={s.id}><Td className="font-medium">{task(s)}</Td><Td>{t(`sched.${s.kind}` as never)}</Td><Td>{formatDate(s.next_run_at, locale)}</Td>
              <Td>{s.task_type === "dns_discovery" ? s.last_discovery ? <Link to={`/targets?discovery=${s.last_discovery.id}`} className="row-link"><Badge tone={s.last_discovery.status === "done" ? "success" : "warning"}>{t(`dd.status.${s.last_discovery.status}` as never)}</Badge></Link> : "—" : s.last_run ? <Link to={`/scans/${s.last_run.id}`} className="row-link flex items-center gap-2"><StatusBadge status={s.last_run.status as never} />{formatDuration(s.last_run.duration_seconds)}</Link> : "—"}</Td>
              <Td><Badge tone={s.active ? "success" : "neutral"}>{s.active ? t("sched.active") : t("sched.inactive")}</Badge></Td>
              <Td><div className="flex justify-end gap-2">
                {(s.owner_id === user?.id || atLeast("OPERATOR")) && <Button size="sm" variant="outline" onClick={async () => setDetail(await api<Schedule>(`/schedules/${s.id}`))}>{t("sched.history")}</Button>}
                {(s.owner_id === user?.id || atLeast("OPERATOR")) && (s.task_type !== "dns_discovery" || atLeast("OPERATOR")) && <Button size="sm" variant="outline" aria-label={t("action.edit")} onClick={() => setEditing(s)}><Pencil /></Button>}
                {(s.owner_id === user?.id || atLeast("OPERATOR")) && <ConfirmButton variant="outline" label={<Trash2 className="size-4" />} confirm={t("confirm.delete")} onConfirm={async () => { try { await api(`/schedules/${s.id}`, { method: "DELETE" }); void reload(); } catch (e) { setErr(e); } }} />}
              </div></Td></tr>
          ))}</tbody></Table>
      ) : <Empty>{t("sched.none")}</Empty>}</Card>
      {open && defs && <ScheduleDialog defs={defs} allowDns={atLeast("OPERATOR")} onClose={() => setOpen(false)} onSaved={() => void reload()} />}
      {editing && defs && <ScheduleDialog defs={defs} allowDns={atLeast("OPERATOR")} schedule={editing} onClose={() => setEditing(null)} onSaved={() => void reload()} />}
      {detail && (
        <Dialog open onOpenChange={(o) => !o && setDetail(null)} title={t("sched.history")} wide>
          <Table><thead><tr><Th>{t("sched.dueAt")}</Th><Th>{t("sched.outcome")}</Th><Th>{t("sched.reason")}</Th><Th /></tr></thead>
            <tbody>{(detail.triggers ?? []).map((tr) => <tr key={tr.due_at}><Td>{formatDate(tr.due_at, locale)}</Td><Td><Badge tone={tr.outcome === "triggered" ? "success" : tr.outcome === "error" ? "danger" : "warning"}>{t(`sched.outcome.${tr.outcome}` as never)}</Badge></Td><Td className="text-xs text-muted">{tr.reason}{tr.comparison && <div className="mt-1">{t("sched.comparison", { new: tr.comparison.new_names.length, absent: tr.comparison.not_observed.length, changed: tr.comparison.ip_changed.length })}{!tr.comparison.complete && <div>{t("sched.comparisonPartial")}</div>}</div>}</Td><Td>{tr.run_id && <Link className="text-primary hover:underline" to={`/scans/${tr.run_id}`}>→</Link>}{tr.discovery_id && <Link className="text-primary hover:underline" title={t("sched.openDiscovery")} to={`/targets?discovery=${tr.discovery_id}`}>{t("sched.openDiscovery")}</Link>}</Td></tr>)}</tbody></Table>
          {!(detail.triggers ?? []).length && <Empty>—</Empty>}
        </Dialog>
      )}
    </>
  );
}
