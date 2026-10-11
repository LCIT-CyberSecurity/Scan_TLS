import { Download, Pencil, Plus, Trash2, Upload } from "lucide-react";
import { useState } from "react";
import { api } from "../api/client";
import type { Group, SI, Tag, Target } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CheckList, ConfirmButton, Empty, ErrorNote, PageHeader, TagList, TagsInput, useLoad } from "../components/common";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Dialog } from "../components/ui/dialog";
import { Field, Input, Select, Textarea } from "../components/ui/input";
import { Table, Td, Th } from "../components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useI18n } from "../i18n";

function TargetDialog({ initial, systems, onClose, onSaved }: { initial?: Target; systems: SI[]; onClose: () => void; onSaved: () => void }) {
  const { t } = useI18n();
  const [form, setForm] = useState({ value: initial?.value ?? "", ports: initial?.ports ?? "", description: initial?.description ?? "", tags: initial?.tags ?? [], si_ids: initial?.si_ids ?? [] });
  const [error, setError] = useState<unknown>();
  async function save() {
    try { if (initial) await api(`/targets/${initial.id}`, { method: "PUT", body: form }); else await api("/targets", { method: "POST", body: form }); onSaved(); onClose(); } catch (e) { setError(e); }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={initial ? t("target.edit") : t("target.new")}>
      <div className="space-y-4">
        <Field label={t("target.value")} hint={t("target.valueHint")}><Input value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} /></Field>
        <Field label={t("target.ports")} hint={t("target.portsHint")}><Input value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })} placeholder="443,8443,9000-9010" /></Field>
        <Field label={t("col.description")}><Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        <Field label={t("col.tags")} hint={t("hint.commaSeparated")}><TagsInput value={form.tags} onChange={(tags) => setForm({ ...form, tags })} /></Field>
        <Field label={t("col.si")}><CheckList items={systems.map((s) => ({ id: s.id, label: (s.parent_id ? "↳ " : "") + s.name }))} selected={form.si_ids} onChange={(si_ids) => setForm({ ...form, si_ids })} /></Field>
        <ErrorNote error={error} />
        <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>{t("action.cancel")}</Button><Button onClick={() => void save()}>{t("action.save")}</Button></div>
      </div>
    </Dialog>
  );
}

function ImportDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [text, setText] = useState("");
  const [result, setResult] = useState<{ created: number; existing: number; errors: { line: number; error: string }[] }>();
  const [error, setError] = useState<unknown>();
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={t("target.import")}>
      <div className="space-y-4">
        <Field label={t("target.importHint")}><Textarea value={text} onChange={(e) => setText(e.target.value)} rows={8} placeholder={"www.example.org;443,8443;Site web\n10.0.0.0/24"} /></Field>
        {result && <div className="rounded-sm bg-surface-2 p-3 text-sm">{t("target.imported", { created: result.created, existing: result.existing })}{result.errors.map((e) => <div key={e.line} className="text-danger">#{e.line}: {e.error}</div>)}</div>}
        <ErrorNote error={error} />
        <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>{t("action.close")}</Button><Button onClick={async () => { try { setResult(await api("/targets/import", { method: "POST", body: { text } })); onDone(); } catch (e) { setError(e); } }}>{t("target.import")}</Button></div>
      </div>
    </Dialog>
  );
}

function GroupDialog({ initial, targets, systems, onClose, onSaved }: { initial?: Group; targets: Target[]; systems: SI[]; onClose: () => void; onSaved: () => void }) {
  const { t } = useI18n();
  const [form, setForm] = useState({ name: initial?.name ?? "", description: initial?.description ?? "", target_ids: initial?.target_ids ?? [], tags: initial?.tags ?? [], si_ids: initial?.si_ids ?? [] });
  const [error, setError] = useState<unknown>();
  async function save() { try { if (initial) await api(`/target-groups/${initial.id}`, { method: "PUT", body: form }); else await api("/target-groups", { method: "POST", body: form }); onSaved(); onClose(); } catch (e) { setError(e); } }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={initial ? t("group.edit") : t("group.new")}>
      <div className="space-y-4">
        <Field label={t("col.name")}><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
        <Field label={t("col.description")}><Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        <Field label={t("def.targets")}><CheckList items={targets.map((x) => ({ id: x.id, label: x.value, sub: x.ports }))} selected={form.target_ids} onChange={(target_ids) => setForm({ ...form, target_ids })} /></Field>
        <Field label={t("col.tags")}><TagsInput value={form.tags} onChange={(tags) => setForm({ ...form, tags })} /></Field>
        <Field label={t("col.si")}><CheckList items={systems.map((s) => ({ id: s.id, label: (s.parent_id ? "↳ " : "") + s.name }))} selected={form.si_ids} onChange={(si_ids) => setForm({ ...form, si_ids })} /></Field>
        <ErrorNote error={error} />
        <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>{t("action.cancel")}</Button><Button onClick={() => void save()}>{t("action.save")}</Button></div>
      </div>
    </Dialog>
  );
}

export default function Targets() {
  const { t } = useI18n();
  const { user, atLeast } = useAuth();
  const [q, setQ] = useState("");
  const [tag, setTag] = useState("");
  const [si, setSi] = useState("");
  const [mine, setMine] = useState(false);
  const [dialog, setDialog] = useState<"target" | "import" | "group" | null>(null);
  const [editT, setEditT] = useState<Target | undefined>();
  const [editG, setEditG] = useState<Group | undefined>();
  const [err, setErr] = useState<unknown>();
  const [siForm, setSiForm] = useState({ name: "", parent_id: "" });
  const targets = useLoad(() => api<Target[]>("/targets", { params: { q, tag, si, mine } }), [q, tag, si, mine]);
  const groups = useLoad(() => api<Group[]>("/target-groups"));
  const systems = useLoad(() => api<SI[]>("/information-systems"));
  const tags = useLoad(() => api<Tag[]>("/tags"));
  const siName = (id: string) => systems.data?.find((s) => s.id === id)?.name ?? "";
  const own = (owner: string | null) => atLeast("OPERATOR") || owner === user?.id;
  const remove = (path: string, reload: () => Promise<void>) => async () => { try { await api(path, { method: "DELETE" }); await reload(); } catch (e) { setErr(e); } };

  return (
    <>
      <PageHeader title={t("nav.targets")} />
      <ErrorNote error={err} />
      <Tabs defaultValue="targets">
        <TabsList><TabsTrigger value="targets">{t("targets.targets")}</TabsTrigger><TabsTrigger value="groups">{t("targets.groups")}</TabsTrigger><TabsTrigger value="si">{t("targets.si")}</TabsTrigger><TabsTrigger value="tags">{t("targets.tags")}</TabsTrigger></TabsList>
        <TabsContent value="targets">
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <Input aria-label={t("action.search")} placeholder={t("action.search")} className="w-56" value={q} onChange={(e) => setQ(e.target.value)} />
            <Select aria-label="SI" className="w-60" value={si} onChange={(e) => setSi(e.target.value)}><option value="">{t("filter.allSi")}</option>{systems.data?.map((s) => <option key={s.id} value={s.id}>{s.parent_id ? "↳ " : ""}{s.name}</option>)}</Select>
            <Select aria-label="Tag" className="w-40" value={tag} onChange={(e) => setTag(e.target.value)}><option value="">{t("filter.allTags")}</option>{tags.data?.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</Select>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} />{t("scans.onlyMine")}</label>
            <div className="ml-auto flex gap-2">
              <Button variant="outline" asChild><a href="/api/targets-export" download="targets.txt"><Download />{t("target.export")}</a></Button>
              <Button variant="outline" onClick={() => setDialog("import")}><Upload />{t("target.import")}</Button>
              <Button onClick={() => { setEditT(undefined); setDialog("target"); }}><Plus />{t("target.new")}</Button>
            </div>
          </div>
          <Card>{targets.data?.length ? (
            <Table><thead><tr><Th>{t("target.value")}</Th><Th>{t("col.type")}</Th><Th>{t("target.ports")}</Th><Th>{t("col.tags")}</Th><Th>{t("col.si")}</Th><Th /></tr></thead>
              <tbody>{targets.data.map((x) => (
                <tr key={x.id}><Td className="font-medium">{x.value}<div className="text-xs font-normal text-muted">{x.description}</div></Td><Td><Badge>{x.kind}</Badge></Td><Td>{x.ports || "—"}</Td><Td><TagList tags={x.tags} /></Td><Td className="text-xs">{x.si_ids.map(siName).join(", ")}</Td>
                  <Td>{own(x.owner_id) && <div className="flex justify-end gap-2"><Button size="sm" variant="outline" aria-label={t("action.edit")} onClick={() => { setEditT(x); setDialog("target"); }}><Pencil /></Button><ConfirmButton variant="outline" label={<Trash2 className="size-4" />} confirm={t("confirm.delete")} onConfirm={remove(`/targets/${x.id}`, targets.reload)} /></div>}</Td></tr>
              ))}</tbody></Table>
          ) : <Empty>{t("target.none")}</Empty>}</Card>
        </TabsContent>
        <TabsContent value="groups">
          <div className="mb-3 flex justify-end"><Button onClick={() => { setEditG(undefined); setDialog("group"); }}><Plus />{t("group.new")}</Button></div>
          <Card>{groups.data?.length ? (
            <Table><thead><tr><Th>{t("col.name")}</Th><Th>{t("def.targets")}</Th><Th>{t("col.tags")}</Th><Th /></tr></thead>
              <tbody>{groups.data.map((g) => <tr key={g.id}><Td className="font-medium">{g.name}<div className="text-xs font-normal text-muted">{g.description}</div></Td><Td>{g.target_ids.length}</Td><Td><TagList tags={g.tags} /></Td>
                <Td>{own(g.owner_id) && <div className="flex justify-end gap-2"><Button size="sm" variant="outline" aria-label={t("action.edit")} onClick={() => { setEditG(g); setDialog("group"); }}><Pencil /></Button><ConfirmButton variant="outline" label={<Trash2 className="size-4" />} confirm={t("confirm.delete")} onConfirm={remove(`/target-groups/${g.id}`, groups.reload)} /></div>}</Td></tr>)}</tbody></Table>
          ) : <Empty>{t("group.none")}</Empty>}</Card>
        </TabsContent>
        <TabsContent value="si">
          <Card className="mb-4 p-4"><div className="flex flex-wrap items-end gap-3">
            <Field label={t("col.name")}><Input value={siForm.name} onChange={(e) => setSiForm({ ...siForm, name: e.target.value })} /></Field>
            <Field label={t("si.parent")}><Select value={siForm.parent_id} onChange={(e) => setSiForm({ ...siForm, parent_id: e.target.value })}><option value="">{t("si.none")}</option>{systems.data?.filter((s) => !s.parent_id).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</Select></Field>
            <Button disabled={!siForm.name} onClick={async () => { try { await api("/information-systems", { method: "POST", body: { name: siForm.name, parent_id: siForm.parent_id || null } }); setSiForm({ name: "", parent_id: "" }); await systems.reload(); } catch (e) { setErr(e); } }}><Plus />{t("action.add")}</Button>
          </div></Card>
          <Card>{systems.data?.length ? <Table><thead><tr><Th>{t("col.name")}</Th><Th /></tr></thead><tbody>{systems.data.map((s) => <tr key={s.id}><Td className={s.parent_id ? "pl-10" : "font-medium"}>{s.parent_id && "↳ "}{s.name}</Td><Td>{atLeast("OPERATOR") && <div className="flex justify-end"><ConfirmButton variant="outline" label={<Trash2 className="size-4" />} confirm={t("confirm.delete")} onConfirm={remove(`/information-systems/${s.id}`, systems.reload)} /></div>}</Td></tr>)}</tbody></Table> : <Empty>{t("si.empty")}</Empty>}</Card>
        </TabsContent>
        <TabsContent value="tags">
          <Card><div className="flex flex-wrap gap-2 p-5">{tags.data?.length ? tags.data.map((x) => <Badge key={x.id} tone="primary">{x.name}{atLeast("OPERATOR") && <button aria-label={t("confirm.delete")} className="ml-1 opacity-60 hover:opacity-100" onClick={() => { if (window.confirm(t("confirm.delete"))) void remove(`/tags/${x.id}`, tags.reload)(); }}>×</button>}</Badge>) : <span className="text-sm text-muted">{t("tags.empty")}</span>}</div></Card>
        </TabsContent>
      </Tabs>
      {dialog === "target" && systems.data && <TargetDialog initial={editT} systems={systems.data} onClose={() => setDialog(null)} onSaved={() => { void targets.reload(); void tags.reload(); }} />}
      {dialog === "import" && <ImportDialog onClose={() => setDialog(null)} onDone={() => { void targets.reload(); }} />}
      {dialog === "group" && systems.data && <GroupDialog initial={editG} targets={targets.data ?? []} systems={systems.data} onClose={() => setDialog(null)} onSaved={() => void groups.reload()} />}
    </>
  );
}
