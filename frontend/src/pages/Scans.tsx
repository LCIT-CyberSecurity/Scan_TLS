import { FileText, Play, Plus, Trash2, Pencil } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, downloadUrl } from "../api/client";
import type { Definition, Group, Run, SI, Target, Template, Versioned } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CheckList, ConfirmButton, Empty, ErrorNote, PageHeader, StatusBadge, TagList, TagsInput, useLoad } from "../components/common";
import { Button } from "../components/ui/button";
import { Dialog } from "../components/ui/dialog";
import { Field, Input, Select, Textarea } from "../components/ui/input";
import { Card } from "../components/ui/card";
import { TargetDialog } from "./Targets";
import { DataTable, type Column } from "../components/DataTable";
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
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useState("runs");
  const [editing, setEditing] = useState<Definition | "new" | null>(null);
  // The sidebar's "New scan" button links to /scans?new=1: open the dialog, then drop the parameter.
  useEffect(() => { if (params.get("new")) { setEditing("new"); setParams({}, { replace: true }); } }, [params, setParams]);
  const [error, setError] = useState<unknown>();
  const { data: runs, reload } = useLoad(() => api<Run[]>("/scan-runs", { params: { mine, status } }), [mine, status], 5000);
  const { data: defs, reload: reloadDefs } = useLoad(() => api<Definition[]>("/scan-definitions"));

  async function launch(id: string) {
    try { const r = await api<{ run_id: string; deduplicated: boolean }>(`/scan-definitions/${id}/run`, { method: "POST" }); navigate(`/scans/${r.run_id}`); } catch (e) { setError(e); }
  }
  const canEdit = (d: Definition) => atLeast("OPERATOR") || d.owner_id === user?.id;

  const phaseText = (r: Run) => `${r.status === "running" ? t(`phase.${r.phase}` as never) : ""}${r.progress ? ` ${r.progress.hosts_done}/${r.progress.hosts_total}` : ""}`.trim();
  const runColumns: Column<Run>[] = [
    { key: "name", header: t("col.name"), values: (r) => [r.name], sort: (r) => r.name, render: (r) => <><Link className="row-link" to={`/scans/${r.id}`}>{r.name}</Link>{r.schedule_id && <span className="ml-2 text-xs text-muted">⏱</span>}</> },
    { key: "status", header: t("col.status"), values: (r) => [r.status], render: (r) => <StatusBadge status={r.status} /> },
    { key: "phase", header: t("col.phase"), sort: phaseText, render: (r) => <span className="text-muted">{phaseText(r)}</span> },
    { key: "date", header: t("col.date"), sort: (r) => r.queued_at, values: (r) => [new Date(r.queued_at).toLocaleDateString(locale)], render: (r) => formatDate(r.queued_at, locale) },
    { key: "duration", header: t("col.duration"), sort: (r) => r.duration_seconds ?? -1, render: (r) => formatDuration(r.duration_seconds) },
    { key: "nc", header: t("col.nonCompliant"), sort: (r) => r.summary?.non_compliant_endpoints ?? -1, values: (r) => [String(r.summary?.non_compliant_endpoints ?? "—")], render: (r) => r.summary?.non_compliant_endpoints ?? "—" },
    { key: "actions", header: "", render: (r) => (
      <div className="row-actions">
        {r.reports.some((x) => x.format === "html") && <Button asChild size="sm" variant="outline"><a href={downloadUrl(r.id, "html", true)} target="_blank" rel="noreferrer"><FileText />{t("action.report")}</a></Button>}
        {atLeast("OPERATOR") && !(r.status === "queued" || r.status === "running") && <ConfirmButton variant="outline" label={<Trash2 className="size-4" />} confirm={t("confirm.deleteScan")} onConfirm={async () => { try { await api(`/scan-runs/${r.id}`, { method: "DELETE" }); void reload(); } catch (e) { setError(e); } }} />}
        {(r.status === "queued" || r.status === "running") && (r.initiated_by === user?.id || atLeast("OPERATOR")) && <ConfirmButton variant="outline" label={t("action.cancelScan")} confirm={t("confirm.cancelScan")} onConfirm={async () => { try { await api(`/scan-runs/${r.id}/cancel`, { method: "POST" }); void reload(); } catch (e) { setError(e); } }} />}
      </div>) },
  ];
  const defColumns: Column<Definition>[] = [
    { key: "name", header: t("col.name"), values: (d) => [d.name], sort: (d) => d.name, render: (d) => <>{d.name}<div className="text-xs font-normal text-muted">{d.description}</div></> },
    { key: "tags", header: t("col.tags"), values: (d) => d.tags, render: (d) => <TagList tags={d.tags} /> },
    { key: "targets", header: t("def.targets"), sort: (d) => d.target_ids.length + d.group_ids.length, render: (d) => d.target_ids.length + d.group_ids.length },
    { key: "actions", header: "", render: (d) => (
      <div className="flex justify-end gap-2">
        <Button size="sm" onClick={() => void launch(d.id)}><Play />{t("action.run")}</Button>
        {canEdit(d) && <><Button size="sm" variant="outline" aria-label={t("action.edit")} onClick={() => setEditing(d)}><Pencil /></Button>
          <ConfirmButton variant="outline" label={<Trash2 className="size-4" />} confirm={t("confirm.delete")} onConfirm={async () => { try { await api(`/scan-definitions/${d.id}`, { method: "DELETE" }); void reloadDefs(); } catch (e) { setError(e); } }} /></>}
      </div>) },
  ];

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
          <Card>{runs?.length ? <DataTable rows={runs} rowKey={(r) => r.id} columns={runColumns} /> : <Empty>{t("scans.none")}</Empty>}</Card>
        </TabsContent>
        <TabsContent value="defs">
          <Card>{defs?.length ? <DataTable rows={defs} rowKey={(d) => d.id} columns={defColumns} /> : <Empty>{t("def.none")}</Empty>}</Card>
        </TabsContent>
      </Tabs>
      {editing && <DefinitionDialog initial={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} onSaved={() => { void reloadDefs(); setTab("defs"); }} />}
    </>
  );
}
