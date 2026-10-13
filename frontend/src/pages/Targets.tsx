import { Download, Pencil, Plus, Radar, Trash2, Upload } from "lucide-react";
import { useState } from "react";
import { api } from "../api/client";
import type { Group, SI, Tag, Target } from "../api/types";
import { formatDate } from "../lib/utils";
import { useAuth } from "../auth/AuthContext";
import { DiscoveriesTab, DnsDiscoveryDialog } from "../components/DnsDiscovery";
import { CheckList, ConfirmButton, Empty, ErrorNote, PageHeader, TagList, TagsInput, useLoad } from "../components/common";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Dialog } from "../components/ui/dialog";
import { Field, Input, Select, Textarea } from "../components/ui/input";
import { Table, Td, Th } from "../components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useI18n } from "../i18n";

/** Same classes as the server: a "/" means a subnet, an IPv4/IPv6 literal an address, anything else a host name. */
function detectKind(value: string): "fqdn" | "ip" | "cidr" {
  const v = value.trim();
  if (v.includes("/")) return "cidr";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (v.includes(":") && /^[0-9a-f:.]+$/i.test(v))) return "ip";
  return "fqdn";
}

export function TargetDialog({ initial, systems, onClose, onSaved }: { initial?: Target; systems: SI[]; onClose: () => void; onSaved: (saved: Target) => void }) {
  const { t } = useI18n();
  const [form, setForm] = useState({ name: initial?.name ?? "", value: initial?.value ?? "", ports: initial?.ports ?? "", description: initial?.description ?? "", tags: initial?.tags ?? [], si_ids: initial?.si_ids ?? [] });
  const [kind, setKind] = useState<"fqdn" | "ip" | "cidr">((initial?.kind as "fqdn" | "ip" | "cidr") ?? "fqdn");
  const [error, setError] = useState<unknown>();
  // Creating accepts several values (FQDN, IP, subnet; one per line, comma or space): each becomes a target and,
  // when there are several, they are gathered in a group named after the target.
  const values = initial ? [form.value.trim()] : [...new Set(form.value.split(/[\s,;]+/).map((v) => v.trim()).filter(Boolean))];
  const multiple = values.length > 1;
  async function save() {
    if (!values.length) { setError(new Error(t("target.valueRequired"))); return; }
    if (!multiple && detectKind(values[0]) !== kind) { setError(new Error(t("target.kindMismatch"))); return; }
    try {
      if (initial) { onSaved(await api<Target>(`/targets/${initial.id}`, { method: "PUT", body: form })); onClose(); return; }
      const saved: Target[] = [];
      for (const value of values) {
        const body = { ...form, value, name: multiple ? "" : form.name };
        try { saved.push(await api<Target>("/targets", { method: "POST", body })); }
        catch (e) {
          if ((e as { status?: number }).status !== 409) throw e;   // already known: reuse it
          const all = await api<Target[]>("/targets");
          const known = all.find((x) => x.value === value);
          if (known) saved.push(known); else throw e;
        }
      }
      if (multiple && form.name.trim()) await api("/target-groups", { method: "POST", body: { name: form.name.trim(), description: form.description, target_ids: saved.map((x) => x.id), tags: form.tags, si_ids: form.si_ids } });
      saved.forEach(onSaved); onClose();
    } catch (e) { setError(e); }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={initial ? t("target.edit") : t("target.new")}>
      <div className="space-y-4">
        <Field label={t("target.name")} hint={t("target.nameHint")}><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} maxLength={160} /></Field>
        <div className={`grid items-start gap-4 ${initial ? "sm:grid-cols-[210px_1fr]" : ""}`}>
          <Field label={t("target.type")}><Select className="h-[42px]" value={multiple ? "mixed" : kind} disabled={multiple} onChange={(e) => setKind(e.target.value as "fqdn" | "ip" | "cidr")}>{multiple && <option value="mixed">{t("target.kind.mixed")}</option>}{(["fqdn", "ip", "cidr"] as const).map((k) => <option key={k} value={k}>{t(`target.kind.${k}` as never)}</option>)}</Select></Field>
          <Field label={initial ? t("target.value") : t("target.values")} hint={multiple ? t("target.multiHint", { n: values.length }) : initial ? t(`target.valueHint.${kind}` as never) : t("target.valuesHint")}>
            {initial ? <Input className="h-[42px]" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} /> : <Textarea rows={3} value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder={"www.example.org\n192.0.2.10\n10.20.0.0/24"} />}
          </Field>
        </div>
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
        <Field label={t("def.targets")}><CheckList items={targets.map((x) => ({ id: x.id, label: x.name || x.value, sub: [x.name ? x.value : "", x.ports].filter(Boolean).join(" · ") }))} selected={form.target_ids} onChange={(target_ids) => setForm({ ...form, target_ids })} /></Field>
        <Field label={t("col.tags")}><TagsInput value={form.tags} onChange={(tags) => setForm({ ...form, tags })} /></Field>
        <Field label={t("col.si")}><CheckList items={systems.map((s) => ({ id: s.id, label: (s.parent_id ? "↳ " : "") + s.name }))} selected={form.si_ids} onChange={(si_ids) => setForm({ ...form, si_ids })} /></Field>
        <ErrorNote error={error} />
        <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>{t("action.cancel")}</Button><Button onClick={() => void save()}>{t("action.save")}</Button></div>
      </div>
    </Dialog>
  );
}

/** Where a target comes from, read from the DNS observations a discovery recorded (not from the tag). */
function ProvenanceDialog({ target, onClose }: { target: Target; onClose: () => void }) {
  const { t, locale } = useI18n();
  const data = useLoad(() => api<{ ips: { ip: string }[]; cnames: { name: string }[]; provenance: NonNullable<Target["dns"]> | null }>(`/targets/${target.id}/dns`));
  const p = data.data?.provenance ?? target.dns;
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`${t("target.prov.title")} — ${target.value}`}>
      <div className="space-y-3 text-sm">
        <ErrorNote error={data.error} />
        {p && <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
          <dt className="text-muted">{t("target.prov.filter")}</dt><dd>{p.created ? t("target.prov.created") : t("target.prov.enriched")}</dd>
          <dt className="text-muted">{t("target.prov.domain")}</dt><dd>{p.domains.join(", ") || "—"}</dd>
          <dt className="text-muted">{t("target.prov.methods")}</dt><dd>{p.methods.join(", ") || "—"}</dd>
          <dt className="text-muted">{t("target.prov.first")}</dt><dd>{p.first_seen ? formatDate(p.first_seen, locale) : "—"}</dd>
          <dt className="text-muted">{t("target.prov.last")}</dt><dd>{p.last_seen ? formatDate(p.last_seen, locale) : "—"}</dd>
          <dt className="text-muted">{t("target.prov.ips")}</dt><dd className="break-all">{data.data?.ips.map((i) => i.ip).join(", ") || "—"}</dd>
          <dt className="text-muted">{t("target.prov.cnames")}</dt><dd className="break-all">{data.data?.cnames.map((c) => c.name).join(", ") || "—"}</dd>
        </dl>}
        <p className="text-xs text-muted">{t("target.prov.note")}</p>
        <div className="flex justify-end"><Button variant="outline" onClick={onClose}>{t("action.close")}</Button></div>
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
  const [origin, setOrigin] = useState("");                       // "" | "dns": targets a discovery has seen
  const [imported, setImported] = useState("");                   // a discovery id: only the targets that import processed
  const [prov, setProv] = useState<Target | undefined>();
  const [discoverId, setDiscoverId] = useState<string | undefined>();
  const [discoveries, setDiscoveries] = useState(0);
  const [dialog, setDialog] = useState<"target" | "import" | "group" | "discover" | null>(null);
  const [editT, setEditT] = useState<Target | undefined>();
  const [editG, setEditG] = useState<Group | undefined>();
  const [err, setErr] = useState<unknown>();
  const [siForm, setSiForm] = useState({ name: "", parent_id: "" });
  const targets = useLoad(() => api<Target[]>("/targets", { params: { q, tag, si, mine, provenance: origin, discovery: imported } }), [q, tag, si, mine, origin, imported]);
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
        <TabsList><TabsTrigger value="targets">{t("targets.targets")}</TabsTrigger><TabsTrigger value="groups">{t("targets.groups")}</TabsTrigger><TabsTrigger value="dns">{t("dd.tab")}</TabsTrigger><TabsTrigger value="si">{t("targets.si")}</TabsTrigger><TabsTrigger value="tags">{t("targets.tags")}</TabsTrigger></TabsList>
        <TabsContent value="targets">
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <Input aria-label={t("action.search")} placeholder={t("action.search")} className="w-56" value={q} onChange={(e) => setQ(e.target.value)} />
            <Select aria-label="SI" className="w-60" value={si} onChange={(e) => setSi(e.target.value)}><option value="">{t("filter.allSi")}</option>{systems.data?.map((s) => <option key={s.id} value={s.id}>{s.parent_id ? "↳ " : ""}{s.name}</option>)}</Select>
            <Select aria-label="Tag" className="w-40" value={tag} onChange={(e) => setTag(e.target.value)}><option value="">{t("filter.allTags")}</option>{tags.data?.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</Select>
            <Select aria-label={t("target.prov.filter")} className="w-44" value={origin} onChange={(e) => setOrigin(e.target.value)}><option value="">{t("target.prov.all")}</option><option value="dns">{t("target.prov.dns")}</option></Select>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} />{t("scans.onlyMine")}</label>
            <div className="ml-auto flex flex-wrap gap-2">
              <Button variant="outline" asChild><a href="/api/targets-export" download="targets.txt"><Download />{t("target.export")}</a></Button>
              {atLeast("OPERATOR") && <Button variant="outline" onClick={() => { setDiscoverId(undefined); setDialog("discover"); }}><Radar />{t("discover.title")}</Button>}
              <Button variant="outline" onClick={() => setDialog("import")}><Upload />{t("target.import")}</Button>
              <Button onClick={() => { setEditT(undefined); setDialog("target"); }}><Plus />{t("target.new")}</Button>
            </div>
          </div>
          {imported && <div className="mb-3 flex flex-wrap items-center gap-3 rounded border border-border p-2 text-sm" role="status"><span>{t("target.imported.filter")}</span><Button size="sm" variant="outline" onClick={() => setImported("")}>{t("target.imported.back")}</Button></div>}
          <Card>{targets.data?.length ? (
            <Table><thead><tr><Th>{t("target.name")}</Th><Th>{t("col.type")}</Th><Th>{t("target.ports")}</Th><Th>{t("col.tags")}</Th><Th>{t("col.si")}</Th><Th /></tr></thead>
              <tbody>{targets.data.map((x) => (
                <tr key={x.id}><Td className="font-medium">{x.name || x.value}<div className="text-xs font-normal text-muted">{x.name ? x.value : ""}{x.name && x.description ? " · " : ""}{x.description}</div></Td><Td><Badge>{t(`target.kind.${x.kind}` as never)}</Badge></Td><Td>{x.ports || "—"}</Td><Td><TagList tags={x.tags} />{x.dns && <button type="button" className="mt-1 block" title={`${x.dns.created ? t("target.prov.created") : t("target.prov.enriched")} · ${x.dns.domains.join(", ")}`} aria-label={`${t("target.prov.title")} ${x.value}`} onClick={() => setProv(x)}><Badge tone={x.dns.created ? "success" : "neutral"}>DNS</Badge></button>}</Td><Td className="text-xs">{x.si_ids.map(siName).join(", ")}</Td>
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
        <TabsContent value="dns"><DiscoveriesTab reloadKey={discoveries} onNew={() => { setDiscoverId(undefined); setDialog("discover"); }} onOpen={(id) => { setDiscoverId(id); setDialog("discover"); }} /></TabsContent>
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
      {dialog === "discover" && <DnsDiscoveryDialog resumeId={discoverId} onClose={() => { setDialog(null); setDiscoverId(undefined); setDiscoveries((n) => n + 1); }} onDone={() => { void targets.reload(); void groups.reload(); void tags.reload(); }} onViewTargets={(id) => { setOrigin(""); setQ(""); setTag(""); setSi(""); setMine(false); setImported(id); }} />}
      {prov && <ProvenanceDialog target={prov} onClose={() => setProv(undefined)} />}
      {dialog === "import" && <ImportDialog onClose={() => setDialog(null)} onDone={() => { void targets.reload(); }} />}
      {dialog === "group" && systems.data && <GroupDialog initial={editG} targets={targets.data ?? []} systems={systems.data} onClose={() => setDialog(null)} onSaved={() => void groups.reload()} />}
    </>
  );
}
