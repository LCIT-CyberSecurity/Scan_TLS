import { Archive, Copy, FileDown, Plus, Send } from "lucide-react";
import { useState, type ComponentType } from "react";
import { api } from "../api/client";
import type { Template, TrustStoreSummary, Version, Versioned } from "../api/types";
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

function IpsecPolicyForm({ value, onChange }: { value: Content; onChange: (c: Content) => void }) {
  const fields = [["allowed_versions", "IKE versions"], ["allowed_encryption", "Encryption"], ["allowed_integrity", "Integrity"], ["allowed_prf", "PRF"], ["allowed_dh_groups", "Diffie-Hellman groups"]] as const;
  return <div className="space-y-4">{fields.map(([key, label]) => <Field key={key} label={label} hint="Comma-separated values"><Input value={list(value[key])} onChange={(e) => onChange({ ...value, [key]: split(e.target.value) })} placeholder={key === "allowed_versions" ? "IKEv1, IKEv2" : "AES-GCM, SHA-256, MODP-2048"} /></Field>)}</div>;
}

function SshPolicyForm({ value, onChange }: { value: Content; onChange: (c: Content) => void }) {
  const fields = [["allowed_protocols", "SSH protocols"], ["allowed_kex", "Key exchange"], ["allowed_encryption", "Encryption"], ["allowed_macs", "MAC"], ["allowed_host_keys", "Host keys"]] as const;
  return <div className="space-y-3">{fields.map(([key, label]) => <Field key={key} label={label}>
    <Input value={Array.isArray(value[key]) ? (value[key] as string[]).join(", ") : ""} onChange={(e) => onChange({ ...value, [key]: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })} />
  </Field>)}<Field label="Minimum RSA key size (bits)"><Input type="number" min={1024} max={16384} value={Number(value.minimum_rsa_bits ?? 2048)} onChange={(e) => onChange({ ...value, minimum_rsa_bits: Number(e.target.value) })} /></Field></div>;
}

function SshProfileForm({ value, onChange }: { value: Content; onChange: (c: Content) => void }) {
  const ssh = value.ssh ?? {};
  const patch = (key: string, next: unknown) => onChange({ ...value, ssh: { ...ssh, [key]: next } });
  return <div className="space-y-3"><Field label="TCP ports"><Input value={(ssh.ports ?? [22]).join(", ")} onChange={(e) => patch("ports", e.target.value.split(",").map((x) => Number(x.trim())).filter((x) => Number.isFinite(x)))} /></Field>
    <div className="grid gap-3 sm:grid-cols-3"><Field label="Per-port timeout (1–5 s)"><Input type="number" min={1} max={5} value={ssh.timeout_seconds ?? 2} onChange={(e) => patch("timeout_seconds", Number(e.target.value))} /></Field>
      <Field label="Timeout retries (0–1)"><Input type="number" min={0} max={1} value={ssh.retries ?? 0} onChange={(e) => patch("retries", Number(e.target.value))} /></Field>
      <Field label="Maximum targets (1–1024)"><Input type="number" min={1} max={1024} value={ssh.max_targets ?? 256} onChange={(e) => patch("max_targets", Number(e.target.value))} /></Field></div>
    <Field label="Audit preset"><select className="w-full" value={ssh.preset ?? "quick"} onChange={(e) => patch("preset", e.target.value)}><option value="quick">Quick</option><option value="deep">Deep</option></select></Field>
    <p className="text-xs text-muted">Uses ssh-audit protocol inspection only. No authentication or rate-limit tests are run.</p></div>;
}

function IpsecProfileForm({ value, onChange }: { value: Content; onChange: (c: Content) => void }) {
  const ike = value.ike ?? {};
  const patch = (key: string, v: unknown) => onChange({ ike: { ...ike, [key]: v } });
  return <div className="space-y-4">
    <Field label="IKE versions"><Input value={list(ike.versions ?? ["IKEv1", "IKEv2"])} onChange={(e) => patch("versions", split(e.target.value))} placeholder="IKEv1, IKEv2" /></Field>
    <Field label="UDP ports"><Input value={list(ike.ports ?? [500, 4500])} onChange={(e) => patch("ports", split(e.target.value).map(Number))} placeholder="500, 4500" /></Field>
    <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={ike.nat_t ?? true} onChange={(e) => patch("nat_t", e.target.checked)} />NAT-T encapsulation for UDP 4500</label>
    <div className="grid gap-4 sm:grid-cols-2">
      <Field label="Timeout (ms)"><Input type="number" min={100} max={5000} value={ike.timeout_ms ?? 1000} onChange={(e) => patch("timeout_ms", Number(e.target.value))} /></Field>
      <Field label="Retransmissions (0–2)"><Input type="number" min={0} max={2} value={ike.retries ?? 0} onChange={(e) => patch("retries", Number(e.target.value))} /></Field>
    </div>
    <Field label="IKEv1 transforms (optional)" hint="Separate transforms with semicolons; each transform uses comma-separated ike-scan IDs. Example: 7/256,4,1,14"><Input value={(ike.ikev1_transforms ?? []).join("; ")} onChange={(e) => patch("ikev1_transforms", e.target.value.split(";").map((x: string) => x.trim()).filter(Boolean))} placeholder="7/256,4,1,14" /></Field>
    <p className="text-sm text-muted">Only unauthenticated Main Mode / IKE_SA_INIT discovery is enabled. Aggressive Mode is unavailable. IKEv2 support depends on ike-scan’s experimental default proposal.</p>
  </div>;
}

/** Which authorities verify the chain: the built-in public ones and, explicitly, the private stores (never implicit). */
export function TrustAuthorities({ cert, setCert }: { cert: Content; setCert: (patch: Content) => void }) {
  const { t } = useI18n();
  const { data } = useLoad(() => api<TrustStoreSummary[]>("/trust-stores"));
  const trust = cert.trust ?? {};
  const selected: string[] = Array.isArray(trust.private_stores) ? trust.private_stores : [];
  const privateStores = data?.filter((s) => !s.builtin) ?? [];
  const setTrust = (patch: Content) => setCert({ trust: { ...trust, ...patch } });
  const toggle = (id: string, on: boolean) => {
    const next = on ? [...selected, id] : selected.filter((x) => x !== id);
    const { private_stores: _drop, ...rest } = trust; // eslint-disable-line @typescript-eslint/no-unused-vars
    setCert({ trust: next.length ? { ...rest, private_stores: next } : rest });
  };
  return (
    <fieldset className="ml-6 space-y-2" aria-label={t("prof.trustPrivate")}>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={trust.public_store?.enabled ?? true} onChange={(e) => setTrust({ public_store: { ...trust.public_store, enabled: e.target.checked } })} />{t("prof.trustPublic")}</label>
      <div className="text-sm font-medium">{t("prof.trustPrivate")}</div>
      {privateStores.length ? privateStores.map((s) => (
        <label key={s.id} className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={selected.includes(s.id)} disabled={!s.active && !selected.includes(s.id)} onChange={(e) => toggle(s.id, e.target.checked)} />
          {s.name} <span className="text-xs text-muted">{t("prof.trustStoreInfo", { version: s.version ?? 0, count: s.certificate_count })}</span>{!s.active && <Badge>{t("ts.inactive")}</Badge>}{s.has_expired && <Badge tone="danger">{t("ts.expired")}</Badge>}
        </label>
      )) : <p className="text-xs text-muted">{t("prof.trustNone")}</p>}
      {selected.filter((id) => !privateStores.some((s) => s.id === id)).map((id) => <p key={id} role="alert" className="text-xs text-danger">{id}: ?</p>)}
    </fieldset>
  );
}

function ServiceIdentificationProfileForm({ value, onChange }: { value: Content; onChange: (c: Content) => void }) {
  const { t } = useI18n();
  const settings = value ?? {};
  const patch = (key: string, next: unknown) => onChange({ ...settings, [key]: next });
  return <div className="space-y-3 rounded-sm border border-hairline p-3">
    <h4 className="text-sm font-medium">{t("service.profileTitle" as never)}</h4>
    <div className="grid gap-3 sm:grid-cols-2">
      <Field label={t("service.strategy" as never)}><select className="w-full" value={settings.strategy ?? "fast"} onChange={(e) => patch("strategy", e.target.value)}><option value="fast">{t("service.fast" as never)}</option><option value="detailed">{t("service.detailed" as never)}</option></select></Field>
      <Field label={t("service.maxTargets" as never)}><Input type="number" min={1} max={128} value={settings.max_targets ?? 64} onChange={(e) => patch("max_targets", Number(e.target.value))} /></Field>
      <Field label={t("service.maxServices" as never)}><Input type="number" min={1} max={500} value={settings.max_services ?? 200} onChange={(e) => patch("max_services", Number(e.target.value))} /></Field>
      <Field label={t("service.timeout" as never)}><Input type="number" min={5} max={90} value={settings.timeout_seconds ?? 45} onChange={(e) => patch("timeout_seconds", Number(e.target.value))} /></Field>
      <Field label={t("service.parallelism" as never)}><Input type="number" min={1} max={10} value={settings.max_parallelism ?? 5} onChange={(e) => patch("max_parallelism", Number(e.target.value))} /></Field>
    </div>
    <p className="text-xs text-muted">{t("service.profileHint" as never)}</p>
  </div>;
}

function ProfileForm({ value, onChange, includeServiceSettings = true }: { value: Content; onChange: (c: Content) => void; includeServiceSettings?: boolean }) {
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
      {(cert.trust?.enabled ?? true) && <TrustAuthorities cert={cert} setCert={setCert} />}
      {check(t("prof.revocation"), rev.enabled ?? false, (b) => setCert({ revocation: { ...rev, enabled: b } }))}
      {rev.enabled && <div className="ml-6 space-y-2">{check("OCSP", rev.ocsp ?? true, (b) => setCert({ revocation: { ...rev, ocsp: b } }))}{check("CRL", rev.crl ?? true, (b) => setCert({ revocation: { ...rev, crl: b } }))}</div>}
      <TlsChecksPicker value={value} onChange={onChange} />
      {includeServiceSettings && <ServiceIdentificationProfileForm value={value.service_identification ?? {}} onChange={(service_identification) => onChange({ ...value, service_identification })} />}
    </div>
  );
}

function GenericProfileForm({ value, onChange }: { value: Content; onChange: (c: Content) => void }) {
  return <div className="space-y-6">
    <section className="space-y-3"><h3 className="text-sm font-semibold">TLS</h3><ProfileForm value={value.tls ?? {}} onChange={(tls) => onChange({ ...value, tls })} includeServiceSettings={false} /></section>
    <section className="space-y-3"><h3 className="text-sm font-semibold">VPN IPsec / IKE</h3><IpsecProfileForm value={value.ipsec ?? { ike: { versions: ["IKEv1", "IKEv2"], ports: [500, 4500], timeout_ms: 1000, retries: 0, nat_t: true, aggressive_mode: false } }} onChange={(ipsec) => onChange({ ...value, ipsec })} /></section>
    <section className="space-y-3"><h3 className="text-sm font-semibold">SSH</h3><SshProfileForm value={value} onChange={onChange} /></section>
    <section className="space-y-3"><ServiceIdentificationProfileForm value={value.service_identification ?? {}} onChange={(service_identification) => onChange({ ...value, service_identification })} /></section>
  </div>;
}

function VersionedTab({ kind, technology, Form, blank }: { kind: "policies" | "profiles"; technology: "tls" | "ipsec" | "ssh" | "generic"; Form: ComponentType<{ value: Content; onChange: (c: Content) => void }>; blank: Content }) {
  const { t } = useI18n();
  const { atLeast } = useAuth();
  const { data, reload, error } = useLoad(() => api<Versioned[]>(technology === "tls" ? `/${kind}` : `/${kind}?technology=${technology}`), [kind, technology]);
  const [edit, setEdit] = useState<{ item?: Versioned; name: string; description: string; content: Content } | null>(null);
  const [yaml, setYaml] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>();
  const manage = atLeast("OPERATOR");
  const latest = (i: Versioned): Version => i.versions[0];
  const act = async (fn: () => Promise<unknown>) => { try { await fn(); setErr(undefined); await reload(); } catch (e) { setErr(e); } };

  async function save() {
    if (!edit) return;
    await act(async () => {
      if (edit.item) await api(`/${kind}/${edit.item.id}/versions`, { method: "POST", body: { name: edit.name, description: edit.description, content: edit.content, technology } });
      else await api(`/${kind}`, { method: "POST", body: { name: edit.name, description: edit.description, content: edit.content, technology } });
      setEdit(null);
    });
  }
  return (
    <>
      <div className="mb-3 flex justify-end gap-2">
        {manage && kind === "policies" && technology === "tls" && <Button variant="outline" onClick={() => setYaml("")}><FileDown />{t("pol.importYaml")}</Button>}
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
                  {kind === "policies" && technology === "tls" && <Button size="sm" variant="outline" onClick={async () => setYaml(await fetch(`/api/policies/${i.id}/export-yaml`).then((r) => r.text()))}>YAML</Button>}
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
  const [technology, setTechnology] = useState<"tls" | "ipsec" | "ssh">("tls");
  const { data: tlsCatalog } = useLoad(() => api<TlsCheckSpec[]>("/tls-checks"));
  // New profiles start with the recommended complementary checks; existing profiles are never modified.
  const tlsDefaults = tlsCatalog?.length ? { tls: recommendedSection(tlsCatalog) } : {};
  return (
    <>
      <PageHeader title={t("nav.policies")} subtitle={t("pol.subtitle")} />
      <div className="mb-4 flex gap-2" role="group" aria-label={t("scan.controlType")}>
        <Button variant={technology === "tls" ? "default" : "outline"} onClick={() => setTechnology("tls")}>TLS</Button>
        <Button variant={technology === "ipsec" ? "default" : "outline"} onClick={() => setTechnology("ipsec")}>VPN IPsec</Button>
        <Button variant={technology === "ssh" ? "default" : "outline"} onClick={() => setTechnology("ssh")}>SSH</Button>
      </div>
      <Tabs defaultValue="policies">
        <TabsList><TabsTrigger value="policies">{t("pol.policies")}</TabsTrigger><TabsTrigger value="profiles">{t("pol.profiles")}</TabsTrigger><TabsTrigger value="templates">{t("pol.templates")}</TabsTrigger></TabsList>
        <TabsContent value="policies"><VersionedTab kind="policies" technology={technology} Form={technology === "tls" ? PolicyForm : technology === "ipsec" ? IpsecPolicyForm : SshPolicyForm} blank={technology === "tls" ? { allowed_versions: ["TLSv1.2", "TLSv1.3"], allowed_cipher_algorithms: ["AES-GCM", "CHACHA20-POLY1305"], allowed_signature_hashes: ["SHA-256", "SHA-384", "SHA-512"], minimum_rsa_bits: 2048 } : technology === "ipsec" ? { allowed_versions: ["IKEv1", "IKEv2"], allowed_encryption: ["AES-GCM"], allowed_integrity: ["SHA-256"], allowed_prf: ["PRF-HMAC-SHA2-256"], allowed_dh_groups: ["MODP-2048"] } : { allowed_protocols: ["SSH-2.0"], allowed_kex: ["curve25519-sha256", "diffie-hellman-group14-sha256"], allowed_encryption: ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"], allowed_macs: ["hmac-sha2-256-etm@openssh.com"], allowed_host_keys: ["ssh-ed25519", "rsa-sha2-512"], minimum_rsa_bits: 2048 }} /></TabsContent>
        <TabsContent value="profiles"><VersionedTab kind="profiles" technology="generic" Form={GenericProfileForm} blank={{
          tls: { scan: { ports: "fast", crypto: "standard", resolve_dns: true, workers: 4 }, checks: { certificate: { enabled: true, expires_within_days: 30, trust: { enabled: true }, revocation: { enabled: false } }, ...tlsDefaults } },
          ipsec: { ike: { versions: ["IKEv1", "IKEv2"], ports: [500, 4500], timeout_ms: 1000, retries: 0, nat_t: true, aggressive_mode: false } },
          ssh: { ports: [22], timeout_seconds: 2, preset: "quick", max_targets: 256 },
          service_identification: { strategy: "fast", max_targets: 64, max_services: 200, timeout_seconds: 45, max_parallelism: 5 },
        }} /></TabsContent>
        <TabsContent value="templates"><TemplatesTab /></TabsContent>
      </Tabs>
    </>
  );
}
