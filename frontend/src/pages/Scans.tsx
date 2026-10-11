import { FileText, Play, Plus, Trash2, Pencil } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, downloadUrl } from "../api/client";
import type { Definition, Group, Run, SI, Target, Template, Versioned } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CheckList, ConfirmButton, Empty, ErrorNote, PageHeader, StatusBadge, TagList, TagsInput, useLoad } from "../components/common";
import { Button } from "../components/ui/button";
import { Dialog } from "../components/ui/dialog";
import { Field, Input, Select, Textarea } from "../components/ui/input";
import { Card } from "../components/ui/card";
import { TargetDialog } from "./Targets";
import { Table, Td, Th } from "../components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useI18n } from "../i18n";
import { formatDate, formatDuration } from "../lib/utils";

const blank = { name: "", description: "", target_ids: [] as string[], group_ids: [] as string[], policy_ids: [] as string[], profile_id: "", report_template_id: "", policy_mode: "strict_all", tags: [] as string[], si_ids: [] as string[] };

function DefinitionDialog({ initial, onClose, onSaved }: { initial?: Definition; onClose: () => void; onSaved: () => void }) {
  const { t } = useI18n();
  const [form, setForm] = useState(initial ? { ...blank, ...initial, report_template_id: initial.report_template_id ?? "" } : blank);
  const [error, setError] = useState<unknown>();
  const { data: targets, reload: reloadTargets } = useLoad(() => api<Target[]>("/targets"));
  const [newTarget, setNewTarget] = useState(false);
  const { data: groups } = useLoad(() => api<Group[]>("/target-groups"));
  const { data: policies } = useLoad(() => api<Versioned[]>("/policies"));
  const { data: profiles } = useLoad(() => api<Versioned[]>("/profiles"));
  const { data: templates } = useLoad(() => api<Template[]>("/report-templates"));
  const { data: systems } = useLoad(() => api<SI[]>("/information-systems"));
  const publishedPolicies = policies?.filter((p) => !p.archived && p.versions.some((v) => v.status === "published")) ?? [];
  const publishedProfiles = profiles?.filter((p) => !p.archived && p.versions.some((v) => v.status === "published")) ?? [];
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => setForm((f) => ({ ...f, [k]: v }));

  async function save() {
    try {
      const body = { ...form, report_template_id: form.report_template_id || null };
      if (initial) await api(`/scan-definitions/${initial.id}`, { method: "PUT", body }); else await api("/scan-definitions", { method: "POST", body });
      onSaved(); onClose();
    } catch (e) { setError(e); }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={initial ? t("def.edit") : t("def.new")} wide>
      <div className="space-y-4">
        <Field label={t("col.name")}><Input value={form.name} onChange={(e) => set("name", e.target.value)} /></Field>
        <Field label={t("col.description")}><Textarea value={form.description} onChange={(e) => set("description", e.target.value)} /></Field>
        <Field label={t("def.targets")}><CheckList items={(targets ?? []).map((x) => ({ id: x.id, label: x.value, sub: x.ports }))} selected={form.target_ids} onChange={(v) => set("target_ids", v)} empty={t("def.noTargets")} /></Field>
        <div><Button type="button" variant="outline" size="sm" onClick={() => setNewTarget(true)}><Plus />{t("target.new")}</Button></div>
        <Field label={t("def.groups")}><CheckList items={(groups ?? []).map((x) => ({ id: x.id, label: x.name, sub: `${x.target_ids.length}` }))} selected={form.group_ids} onChange={(v) => set("group_ids", v)} empty={t("def.noGroups")} /></Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("def.profile")}><Select value={form.profile_id} onChange={(e) => set("profile_id", e.target.value)}><option value="">—</option>{publishedProfiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</Select></Field>
          <Field label={t("def.template")}><Select value={form.report_template_id} onChange={(e) => set("report_template_id", e.target.value)}><option value="">{t("def.defaultTemplate")}</option>{templates?.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</Select></Field>
        </div>
        <Field label={t("def.policies")} hint={t("def.policiesHint")}><CheckList items={publishedPolicies.map((p) => ({ id: p.id, label: p.name, sub: `v${p.versions.find((v) => v.status === "published")?.version}` }))} selected={form.policy_ids} onChange={(v) => set("policy_ids", v)} empty={t("def.noPolicies")} /></Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("col.si")}><CheckList items={(systems ?? []).map((s) => ({ id: s.id, label: (s.parent_id ? "↳ " : "") + s.name }))} selected={form.si_ids} onChange={(v) => set("si_ids", v)} /></Field>
          <Field label={t("col.tags")} hint={t("hint.commaSeparated")}><TagsInput value={form.tags} onChange={(v) => set("tags", v)} /></Field>
        </div>
        <ErrorNote error={error} />
        <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>{t("action.cancel")}</Button><Button onClick={() => void save()}>{t("action.save")}</Button></div>
      </div>
      {newTarget && systems && <TargetDialog systems={systems} onClose={() => setNewTarget(false)} onSaved={(saved) => { void reloadTargets(); setForm((f) => ({ ...f, target_ids: [...f.target_ids, saved.id] })); }} />}
    </Dialog>
  );
}

export default function Scans() {
  const { t, locale } = useI18n();
  const { user, atLeast } = useAuth();
  const navigate = useNavigate();
  const [mine, setMine] = useState(!atLeast("OPERATOR"));
  const [status, setStatus] = useState("");
  const [tab, setTab] = useState("runs");
  const [editing, setEditing] = useState<Definition | "new" | null>(null);
  const [error, setError] = useState<unknown>();
  const { data: runs, reload } = useLoad(() => api<Run[]>("/scan-runs", { params: { mine, status } }), [mine, status], 5000);
  const { data: defs, reload: reloadDefs } = useLoad(() => api<Definition[]>("/scan-definitions"));

  async function launch(id: string) {
    try { const r = await api<{ run_id: string; deduplicated: boolean }>(`/scan-definitions/${id}/run`, { method: "POST" }); navigate(`/scans/${r.run_id}`); } catch (e) { setError(e); }
  }
  const canEdit = (d: Definition) => atLeast("OPERATOR") || d.owner_id === user?.id;

  return (
    <>
      <PageHeader title={t("nav.scans")} actions={<Button onClick={() => setEditing("new")}><Plus />{t("def.new")}</Button>} />
      <ErrorNote error={error} />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList><TabsTrigger value="runs">{t("scans.runs")}</TabsTrigger><TabsTrigger value="defs">{t("scans.definitions")}</TabsTrigger></TabsList>
        <TabsContent value="runs">
          <div className="mb-3 flex flex-wrap items-center gap-3">
            {atLeast("OPERATOR") && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} />{t("scans.onlyMine")}</label>}
            <Select aria-label={t("col.status")} className="w-44" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">{t("filter.allStatuses")}</option>{["queued", "running", "completed", "partial", "failed", "cancelled", "expired"].map((s) => <option key={s} value={s}>{t(`status.${s}` as never)}</option>)}</Select>
          </div>
          <Card>{runs?.length ? (
            <Table><thead><tr><Th>{t("col.name")}</Th><Th>{t("col.status")}</Th><Th>{t("col.phase")}</Th><Th>{t("col.date")}</Th><Th>{t("col.duration")}</Th><Th>{t("col.nonCompliant")}</Th><Th /></tr></thead>
              <tbody>{runs.map((r) => (
                <tr key={r.id}><Td><Link className="row-link" to={`/scans/${r.id}`}>{r.name}</Link>{r.schedule_id && <span className="ml-2 text-xs text-muted">⏱</span>}</Td><Td><StatusBadge status={r.status} /></Td>
                  <Td className="text-muted">{r.status === "running" ? t(`phase.${r.phase}` as never) : ""}{r.progress ? ` ${r.progress.hosts_done}/${r.progress.hosts_total}` : ""}</Td>
                  <Td>{formatDate(r.queued_at, locale)}</Td><Td>{formatDuration(r.duration_seconds)}</Td><Td>{r.summary?.non_compliant_endpoints ?? "—"}</Td>
                  <Td><div className="row-actions">{r.reports.some((x) => x.format === "html") && <Button asChild size="sm" variant="outline"><a href={downloadUrl(r.id, "html", true)} target="_blank" rel="noreferrer"><FileText />{t("action.report")}</a></Button>}{(r.status === "queued" || r.status === "running") && (r.initiated_by === user?.id || atLeast("OPERATOR")) && <ConfirmButton variant="outline" label={t("action.cancelScan")} confirm={t("confirm.cancelScan")} onConfirm={async () => { try { await api(`/scan-runs/${r.id}/cancel`, { method: "POST" }); void reload(); } catch (e) { setError(e); } }} />}</div></Td></tr>
              ))}</tbody></Table>
          ) : <Empty>{t("scans.none")}</Empty>}</Card>
        </TabsContent>
        <TabsContent value="defs">
          <Card>{defs?.length ? (
            <Table><thead><tr><Th>{t("col.name")}</Th><Th>{t("col.tags")}</Th><Th>{t("def.targets")}</Th><Th /></tr></thead>
              <tbody>{defs.map((d) => (
                <tr key={d.id}><Td className="font-medium">{d.name}<div className="text-xs font-normal text-muted">{d.description}</div></Td><Td><TagList tags={d.tags} /></Td><Td>{d.target_ids.length + d.group_ids.length}</Td>
                  <Td><div className="flex justify-end gap-2">
                    <Button size="sm" onClick={() => void launch(d.id)}><Play />{t("action.run")}</Button>
                    {canEdit(d) && <><Button size="sm" variant="outline" aria-label={t("action.edit")} onClick={() => setEditing(d)}><Pencil /></Button>
                      <ConfirmButton variant="outline" label={<Trash2 className="size-4" />} confirm={t("confirm.delete")} onConfirm={async () => { try { await api(`/scan-definitions/${d.id}`, { method: "DELETE" }); void reloadDefs(); } catch (e) { setError(e); } }} /></>}
                  </div></Td></tr>
              ))}</tbody></Table>
          ) : <Empty>{t("def.none")}</Empty>}</Card>
        </TabsContent>
      </Tabs>
      {editing && <DefinitionDialog initial={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} onSaved={() => { void reloadDefs(); setTab("defs"); }} />}
    </>
  );
}
