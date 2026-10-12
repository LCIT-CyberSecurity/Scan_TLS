import { Archive, Copy, FileDown, Plus, Send } from "lucide-react";
import { useState } from "react";
import { api } from "../api/client";
import type { Template, Version, Versioned } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Empty, ErrorNote, Note, PageHeader, useLoad } from "../components/common";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Dialog } from "../components/ui/dialog";
import { Field, Input, Textarea } from "../components/ui/input";
import { Table, Td, Th } from "../components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { TlsChecksPicker } from "../components/TlsChecksPicker";
import { useI18n } from "../i18n";
import { recommendedSection, type TlsCheckSpec } from "../lib/tlsChecks";

type Content = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const list = (v: unknown) => (Array.isArray(v) ? v.join(", ") : "");
const split = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

function PolicyForm({ value, onChange }: { value: Content; onChange: (c: Content) => void }) {
  const { t } = useI18n();
  return (
    <div className="space-y-4">
      <Field label={t("pol.versions")} hint={t("hint.commaSeparated")}><Input value={list(value.allowed_versions)} onChange={(e) => onChange({ ...value, allowed_versions: split(e.target.value) })} placeholder="TLSv1.2, TLSv1.3" /></Field>
      <Field label={t("pol.ciphers")}><Input value={list(value.allowed_cipher_algorithms)} onChange={(e) => onChange({ ...value, allowed_cipher_algorithms: split(e.target.value) })} placeholder="AES-GCM, CHACHA20-POLY1305" /></Field>
      <Field label={t("pol.hashes")}><Input value={list(value.allowed_signature_hashes)} onChange={(e) => onChange({ ...value, allowed_signature_hashes: split(e.target.value) })} placeholder="SHA-256, SHA-384" /></Field>
      <Field label={t("pol.rsa")}><Input type="number" value={value.minimum_rsa_bits ?? 2048} onChange={(e) => onChange({ ...value, minimum_rsa_bits: Number(e.target.value) })} /></Field>
    </div>
  );
}

function ProfileForm({ value, onChange }: { value: Content; onChange: (c: Content) => void }) {
  const { t } = useI18n();
  const scan = value.scan ?? {};
  const cert = value.checks?.certificate ?? {};
  const setScan = (k: string, v: unknown) => onChange({ ...value, scan: { ...scan, [k]: v } });
  const setCert = (patch: Content) => onChange({ ...value, checks: { ...value.checks, certificate: { ...cert, ...patch } } });
  const rev = cert.revocation ?? {};
  const check = (label: string, checked: boolean, on: (b: boolean) => void) => <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={checked} onChange={(e) => on(e.target.checked)} />{label}</label>;
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("prof.ports")} hint={t("prof.portsHint")}><Input value={String(scan.ports ?? "fast")} onChange={(e) => setScan("ports", e.target.value)} /></Field>
        <Field label={t("prof.crypto")}><select className="w-full" value={scan.crypto ?? "standard"} onChange={(e) => setScan("crypto", e.target.value)}><option value="standard">standard</option><option value="pqc">pqc</option></select></Field>
        <Field label={t("prof.workers")}><Input type="number" min={1} max={32} value={scan.workers ?? 4} onChange={(e) => setScan("workers", Number(e.target.value))} /></Field>
        <Field label={t("prof.expires")}><Input type="number" min={1} value={cert.expires_within_days ?? 30} onChange={(e) => setCert({ expires_within_days: Number(e.target.value) })} /></Field>
      </div>
      {check(t("prof.dns"), scan.resolve_dns ?? true, (b) => setScan("resolve_dns", b))}
      {check(t("prof.trust"), cert.trust?.enabled ?? true, (b) => setCert({ trust: { ...cert.trust, enabled: b } }))}
      {check(t("prof.revocation"), rev.enabled ?? false, (b) => setCert({ revocation: { ...rev, enabled: b } }))}
      {rev.enabled && <div className="ml-6 space-y-2">{check("OCSP", rev.ocsp ?? true, (b) => setCert({ revocation: { ...rev, ocsp: b } }))}{check("CRL", rev.crl ?? true, (b) => setCert({ revocation: { ...rev, crl: b } }))}</div>}
      <TlsChecksPicker value={value} onChange={onChange} />
    </div>
  );
}

function VersionedTab({ kind, Form, blank }: { kind: "policies" | "profiles"; Form: typeof PolicyForm; blank: Content }) {
  const { t } = useI18n();
  const { atLeast } = useAuth();
  const { data, reload, error } = useLoad(() => api<Versioned[]>(`/${kind}`));
  const [edit, setEdit] = useState<{ item?: Versioned; name: string; description: string; content: Content } | null>(null);
  const [yaml, setYaml] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>();
  const manage = atLeast("OPERATOR");
  const latest = (i: Versioned): Version => i.versions[0];
  const act = async (fn: () => Promise<unknown>) => { try { await fn(); setErr(undefined); await reload(); } catch (e) { setErr(e); } };

  async function save() {
    if (!edit) return;
    await act(async () => {
      if (edit.item) await api(`/${kind}/${edit.item.id}/versions`, { method: "POST", body: { name: edit.name, description: edit.description, content: edit.content } });
      else await api(`/${kind}`, { method: "POST", body: { name: edit.name, description: edit.description, content: edit.content } });
      setEdit(null);
    });
  }
  return (
    <>
      <div className="mb-3 flex justify-end gap-2">
        {manage && kind === "policies" && <Button variant="outline" onClick={() => setYaml("")}><FileDown />{t("pol.importYaml")}</Button>}
        {manage && <Button onClick={() => setEdit({ name: "", description: "", content: blank })}><Plus />{t("action.new")}</Button>}
      </div>
      <ErrorNote error={error ?? err} />
      <Card className="mt-3">{data?.length ? (
        <Table><thead><tr><Th>{t("col.name")}</Th><Th>{t("pol.published")}</Th><Th>{t("pol.latest")}</Th><Th /></tr></thead>
          <tbody>{data.map((i) => {
            const published = i.versions.find((v) => v.status === "published");
            const last = latest(i);
            return (
              <tr key={i.id}><Td className="font-medium">{i.name}{i.archived && <Badge className="ml-2">{t("pol.archived")}</Badge>}<div className="text-xs font-normal text-muted">{i.description}</div></Td>
                <Td>{published ? <Badge tone="success">v{published.version}</Badge> : "—"}</Td>
                <Td>{last.status === "draft" ? <Badge tone="warning">v{last.version} {t("pol.draft")}</Badge> : `v${last.version}`}</Td>
                <Td>{manage && <div className="flex justify-end gap-2">
                  <Button size="sm" variant="outline" onClick={() => setEdit({ item: i, name: i.name, description: i.description, content: last.content })}>{t("action.edit")}</Button>
                  {last.status === "draft" && <Button size="sm" onClick={() => void act(() => api(`/${kind}/${i.id}/publish`, { method: "POST" }))}><Send />{t("pol.publish")}</Button>}
                  <Button size="sm" variant="outline" aria-label={t("pol.duplicate")} onClick={() => void act(() => api(`/${kind}/${i.id}/duplicate`, { method: "POST" }))}><Copy /></Button>
                  {kind === "policies" && <Button size="sm" variant="outline" onClick={async () => setYaml(await fetch(`/api/policies/${i.id}/export-yaml`).then((r) => r.text()))}>YAML</Button>}
                  <Button size="sm" variant="outline" aria-label={t("pol.archive")} onClick={() => void act(() => api(`/${kind}/${i.id}/archive`, { method: "POST" }))}><Archive /></Button>
                </div>}</Td></tr>
            );
          })}</tbody></Table>
      ) : <Empty>—</Empty>}</Card>
      {edit && (
        <Dialog open onOpenChange={(o) => !o && setEdit(null)} title={edit.item ? t("pol.newVersion") : t("action.new")}>
          <div className="space-y-4">
            {edit.item && <Note tone="info">{t("pol.immutableHint")}</Note>}
            <Field label={t("col.name")}><Input value={edit.name} disabled={!!edit.item} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /></Field>
            <Field label={t("col.description")}><Input value={edit.description} onChange={(e) => setEdit({ ...edit, description: e.target.value })} /></Field>
            <Form value={edit.content} onChange={(content) => setEdit({ ...edit, content })} />
            <ErrorNote error={err} />
            <div className="flex justify-end gap-2"><Button variant="outline" onClick={() => setEdit(null)}>{t("action.cancel")}</Button><Button onClick={() => void save()}>{t("action.save")}</Button></div>
          </div>
        </Dialog>
      )}
      {yaml !== null && (
        <Dialog open onOpenChange={(o) => !o && setYaml(null)} title="YAML" wide>
          <Textarea rows={14} value={yaml} onChange={(e) => setYaml(e.target.value)} className="font-mono text-xs" />
          <div className="mt-4 flex justify-end gap-2"><Button variant="outline" onClick={() => setYaml(null)}>{t("action.close")}</Button>{manage && <Button onClick={() => void act(async () => { await api("/policies/import-yaml", { method: "POST", body: { yaml } }); setYaml(null); })}>{t("pol.importYaml")}</Button>}</div>
        </Dialog>
      )}
    </>
  );
}

function TemplatesTab() {
  const { t } = useI18n();
  const { atLeast } = useAuth();
  const { data, reload } = useLoad(() => api<Template[]>("/report-templates"));
  const [form, setForm] = useState({ name: "", description: "", export_formats: ["html", "md", "csv", "cbom"], organization_name: "", accent_color: "", logo: "" });
  const [err, setErr] = useState<unknown>();
  const toggle = (f: string) => setForm((s) => ({ ...s, export_formats: s.export_formats.includes(f) ? s.export_formats.filter((x) => x !== f) : [...s.export_formats, f] }));
  return (
    <>
      {atLeast("OPERATOR") && <Card className="mb-4 p-4"><div className="flex flex-wrap items-end gap-3">
        <Field label={t("col.name")}><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
        <div className="flex gap-3 pb-2">{["html", "md", "csv", "cbom"].map((f) => <label key={f} className="flex items-center gap-1.5 text-sm"><input type="checkbox" checked={form.export_formats.includes(f)} onChange={() => toggle(f)} />{f.toUpperCase()}</label>)}</div>
      </div>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <Field label={t("tpl.org")}><Input value={form.organization_name} onChange={(e) => setForm({ ...form, organization_name: e.target.value })} /></Field>
        <Field label={t("tpl.accent")}><input type="color" className="h-10 w-16 p-1" value={form.accent_color || "#4b2d8a"} onChange={(e) => setForm({ ...form, accent_color: e.target.value })} /></Field>
        <Field label={t("tpl.logo")}><input type="file" accept="image/png,image/jpeg,image/svg+xml" aria-label={t("tpl.logo")} onChange={(e) => { const f = e.target.files?.[0]; if (!f) return; const r = new FileReader(); r.onload = () => setForm((s) => ({ ...s, logo: String(r.result) })); r.readAsDataURL(f); }} /></Field>
        <Button disabled={!form.name} onClick={async () => { try { await api("/report-templates", { method: "POST", body: form }); setForm({ ...form, name: "", logo: "" }); await reload(); } catch (e) { setErr(e); } }}><Plus />{t("action.add")}</Button>
      </div>
      <p className="mt-2 text-xs text-muted">{t("tpl.brandHint")}</p><div className="mt-2"><ErrorNote error={err} /></div></Card>}
      <Card>{data?.length ? <Table><thead><tr><Th>{t("col.name")}</Th><Th>{t("tpl.formats")}</Th></tr></thead><tbody>{data.map((x) => <tr key={x.id}><Td className="font-medium">{x.name}</Td><Td>{x.export_formats.map((f) => <Badge key={f} className="mr-1">{f.toUpperCase()}</Badge>)}{x.organization_name && <span className="ml-2 text-xs text-muted">{x.organization_name}</span>}{x.accent_color && <i className="ml-2 inline-block size-3 rounded-full align-middle" style={{ background: x.accent_color }} />}{x.logo && <img alt="" src={x.logo} className="ml-2 inline h-5 align-middle" />}</Td></tr>)}</tbody></Table> : <Empty>{t("tpl.none")}</Empty>}</Card>
    </>
  );
}

export default function Policies() {
  const { t } = useI18n();
  const { data: tlsCatalog } = useLoad(() => api<TlsCheckSpec[]>("/tls-checks"));
  // New profiles start with the recommended complementary checks; existing profiles are never modified.
  const tlsDefaults = tlsCatalog?.length ? { tls: recommendedSection(tlsCatalog) } : {};
  return (
    <>
      <PageHeader title={t("nav.policies")} subtitle={t("pol.subtitle")} />
      <Tabs defaultValue="policies">
        <TabsList><TabsTrigger value="policies">{t("pol.policies")}</TabsTrigger><TabsTrigger value="profiles">{t("pol.profiles")}</TabsTrigger><TabsTrigger value="templates">{t("pol.templates")}</TabsTrigger></TabsList>
        <TabsContent value="policies"><VersionedTab kind="policies" Form={PolicyForm} blank={{ allowed_versions: ["TLSv1.2", "TLSv1.3"], allowed_cipher_algorithms: ["AES-GCM", "CHACHA20-POLY1305"], allowed_signature_hashes: ["SHA-256", "SHA-384", "SHA-512"], minimum_rsa_bits: 2048 }} /></TabsContent>
        <TabsContent value="profiles"><VersionedTab kind="profiles" Form={ProfileForm} blank={{ scan: { ports: "fast", crypto: "standard", resolve_dns: true, workers: 4 }, checks: { certificate: { enabled: true, expires_within_days: 30, trust: { enabled: true }, revocation: { enabled: false } }, ...tlsDefaults } }} /></TabsContent>
        <TabsContent value="templates"><TemplatesTab /></TabsContent>
      </Tabs>
    </>
  );
}
