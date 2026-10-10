import { Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Definition, Schedule } from "../api/types";
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

function ScheduleDialog({ defs, onClose, onSaved }: { defs: Definition[]; onClose: () => void; onSaved: () => void }) {
  const { t } = useI18n();
  const [definition, setDefinition] = useState(defs[0]?.id ?? "");
  const [kind, setKind] = useState("daily");
  const [time, setTime] = useState("03:00");
  const [weekday, setWeekday] = useState(0);
  const [day, setDay] = useState(1);
  const [at, setAt] = useState("");
  const [expr, setExpr] = useState("0 3 * * 1");
  const [error, setError] = useState<unknown>();
  const params = kind === "once" ? { at } : kind === "daily" ? { time } : kind === "weekly" ? { time, weekday } : kind === "monthly" ? { time, day } : { expr };
  async function save() {
    try { await api("/schedules", { method: "POST", body: { definition_id: definition, kind, params, timezone: TZ } }); onSaved(); onClose(); } catch (e) { setError(e); }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={t("sched.new")}>
      <div className="space-y-4">
        <Field label={t("sched.definition")}><Select value={definition} onChange={(e) => setDefinition(e.target.value)}>{defs.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</Select></Field>
        <Field label={t("sched.frequency")}><Select value={kind} onChange={(e) => setKind(e.target.value)}>{["once", "daily", "weekly", "monthly", "cron"].map((k) => <option key={k} value={k}>{t(`sched.${k}` as never)}</option>)}</Select></Field>
        {kind === "once" && <Field label={t("sched.at")}><Input type="datetime-local" value={at} onChange={(e) => setAt(e.target.value)} /></Field>}
        {["daily", "weekly", "monthly"].includes(kind) && <Field label={t("sched.time")}><Input type="time" value={time} onChange={(e) => setTime(e.target.value)} /></Field>}
        {kind === "weekly" && <Field label={t("sched.weekday")}><Select value={weekday} onChange={(e) => setWeekday(Number(e.target.value))}>{[0, 1, 2, 3, 4, 5, 6].map((d) => <option key={d} value={d}>{new Date(2024, 0, 1 + d).toLocaleDateString(undefined, { weekday: "long" })}</option>)}</Select></Field>}
        {kind === "monthly" && <Field label={t("sched.day")}><Input type="number" min={1} max={28} value={day} onChange={(e) => setDay(Number(e.target.value))} /></Field>}
        {kind === "cron" && <Field label={t("sched.cron")} hint={t("sched.cronHint")}><Input value={expr} onChange={(e) => setExpr(e.target.value)} /></Field>}
        <p className="text-xs text-muted">{t("sched.timezone")}: {TZ}</p>
        <ErrorNote error={error} />
        <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>{t("action.cancel")}</Button><Button onClick={() => void save()}>{t("action.save")}</Button></div>
      </div>
    </Dialog>
  );
}

export default function Schedules() {
  const { t, locale } = useI18n();
  const { user, atLeast } = useAuth();
  const { data, reload, error } = useLoad(() => api<Schedule[]>("/schedules"), [], 10000);
  const { data: defs } = useLoad(() => api<Definition[]>("/scan-definitions"));
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<Schedule | null>(null);
  const [err, setErr] = useState<unknown>();
  const name = (id: string) => defs?.find((d) => d.id === id)?.name ?? id.slice(0, 8);
  return (
    <>
      <PageHeader title={t("nav.schedules")} subtitle={atLeast("OPERATOR") ? t("sched.allSubtitle") : t("sched.mineSubtitle")} actions={<Button onClick={() => setOpen(true)} disabled={!defs?.length}><Plus />{t("sched.new")}</Button>} />
      <ErrorNote error={error ?? err} />
      <Card>{data?.length ? (
        <Table><thead><tr><Th>{t("sched.definition")}</Th><Th>{t("sched.frequency")}</Th><Th>{t("sched.next")}</Th><Th>{t("sched.last")}</Th><Th>{t("col.status")}</Th><Th /></tr></thead>
          <tbody>{data.map((s) => (
            <tr key={s.id}><Td className="font-medium">{name(s.definition_id)}</Td><Td>{t(`sched.${s.kind}` as never)}</Td><Td>{formatDate(s.next_run_at, locale)}</Td>
              <Td>{s.last_run ? <Link to={`/scans/${s.last_run.id}`} className="flex items-center gap-2 text-primary hover:underline"><StatusBadge status={s.last_run.status as never} />{formatDuration(s.last_run.duration_seconds)}</Link> : "—"}</Td>
              <Td><Badge tone={s.active ? "success" : "neutral"}>{s.active ? t("sched.active") : t("sched.inactive")}</Badge></Td>
              <Td><div className="flex justify-end gap-2">
                {(s.owner_id === user?.id || atLeast("OPERATOR")) && <Button size="sm" variant="outline" onClick={async () => setDetail(await api<Schedule>(`/schedules/${s.id}`))}>{t("sched.history")}</Button>}
                {(s.owner_id === user?.id || atLeast("OPERATOR")) && <ConfirmButton variant="outline" label={<Trash2 className="size-4" />} confirm={t("confirm.delete")} onConfirm={async () => { try { await api(`/schedules/${s.id}`, { method: "DELETE" }); void reload(); } catch (e) { setErr(e); } }} />}
              </div></Td></tr>
          ))}</tbody></Table>
      ) : <Empty>{t("sched.none")}</Empty>}</Card>
      {open && defs && <ScheduleDialog defs={defs} onClose={() => setOpen(false)} onSaved={() => void reload()} />}
      {detail && (
        <Dialog open onOpenChange={(o) => !o && setDetail(null)} title={t("sched.history")} wide>
          <Table><thead><tr><Th>{t("sched.dueAt")}</Th><Th>{t("sched.outcome")}</Th><Th>{t("sched.reason")}</Th><Th /></tr></thead>
            <tbody>{(detail.triggers ?? []).map((tr) => <tr key={tr.due_at}><Td>{formatDate(tr.due_at, locale)}</Td><Td><Badge tone={tr.outcome === "triggered" ? "success" : tr.outcome === "error" ? "danger" : "warning"}>{t(`sched.outcome.${tr.outcome}` as never)}</Badge></Td><Td className="text-xs text-muted">{tr.reason}</Td><Td>{tr.run_id && <Link className="text-primary hover:underline" to={`/scans/${tr.run_id}`}>→</Link>}</Td></tr>)}</tbody></Table>
          {!(detail.triggers ?? []).length && <Empty>—</Empty>}
        </Dialog>
      )}
    </>
  );
}
