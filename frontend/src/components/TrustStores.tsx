import { Plus, ShieldCheck, Upload } from "lucide-react";
import { useState } from "react";
import { api } from "../api/client";
import type { TrustCert, TrustInspect, TrustStoreDetail, TrustStoreSummary } from "../api/types";
import { Empty, ErrorNote, Note, useLoad } from "./common";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { Dialog } from "./ui/dialog";
import { Field, Input, Select } from "./ui/input";
import { Table, Td, Th } from "./ui/table";
import { useI18n } from "../i18n";
import { formatDate } from "../lib/utils";

export interface PickedFile { filename: string; content_b64: string }

/** Reads files as base64: the backend inspects the real content, never the name or the extension. */
export async function readFiles(list: FileList | null): Promise<PickedFile[]> {
  const out: PickedFile[] = [];
  for (const file of Array.from(list ?? [])) {
    const bytes = new Uint8Array(await new Promise<ArrayBuffer>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as ArrayBuffer);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(file);
    }));
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    out.push({ filename: file.name, content_b64: btoa(binary) });
  }
  return out;
}

const short = (fp: string) => `${fp.slice(0, 16)}…`;

export function CertDetail({ cert, onRemove }: { cert: Omit<TrustCert, "expired" | "expires_in_days"> & Partial<Pick<TrustCert, "expired" | "expires_in_days">>; onRemove?: () => void }) {
  const { t, locale } = useI18n();
  const rows: [string, string][] = [
    [t("ts.subject"), cert.subject], [t("ts.issuer"), cert.issuer], [t("ts.serial"), cert.serial],
    [t("ts.validity"), `${formatDate(cert.not_before, locale)} → ${formatDate(cert.not_after, locale)}`],
    [t("ts.key"), `${cert.key_type}${cert.key_size ? ` ${cert.key_size}` : ""}`], [t("ts.signature"), cert.signature_algorithm],
    [t("ts.basic"), cert.basic_constraints ? `CA:${cert.basic_constraints.ca ? "TRUE" : "FALSE"}${cert.basic_constraints.path_length !== null ? `, pathlen:${cert.basic_constraints.path_length}` : ""}` : "—"],
    [t("ts.keyUsage"), cert.key_usage?.join(", ") ?? "—"], [t("ts.fingerprint"), cert.fingerprint_sha256],
  ];
  return (
    <div className="cert-detail space-y-1 rounded-sm bg-surface-2 p-3 text-xs">
      {rows.map(([k, v]) => <div key={k} className="grid gap-2 sm:grid-cols-[10rem_1fr]"><span className="text-muted">{k}</span><span className="break-all font-mono">{v}</span></div>)}
      {onRemove && <div className="pt-2"><Button size="sm" variant="outline" onClick={onRemove}>{t("ts.remove")}</Button></div>}
    </div>
  );
}

function RoleBadge({ role }: { role: string | null }) {
  const { t } = useI18n();
  if (!role) return null;
  return <Badge tone={role === "anchor" ? "primary" : "neutral"} title={role === "anchor" ? undefined : t("ts.intermediateHint")}>{role === "anchor" ? t("ts.anchor") : t("ts.intermediate")}</Badge>;
}

/** Files picker with the server-side dry run: what would be stored, or why a file is refused. */
function ImportPicker({ onFiles }: { onFiles: (f: PickedFile[]) => void }) {
  const { t } = useI18n();
  const [preview, setPreview] = useState<TrustInspect | null>(null);
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  async function pick(list: FileList | null) {
    setError(undefined); setPreview(null);
    const picked = await readFiles(list);
    onFiles(picked);
    if (!picked.length) return;
    setBusy(true);
    try { setPreview(await api<TrustInspect>("/admin/trust-stores/inspect", { method: "POST", body: { files: picked } })); } catch (e) { setError(e); } finally { setBusy(false); }
  }
  return (
    <div className="space-y-3">
      <Field label={t("ts.files")} hint={t("ts.filesHint")}><input type="file" multiple accept=".pem,.crt,.cer" aria-label={t("ts.files")} onChange={(e) => void pick(e.target.files)} /></Field>
      <ErrorNote error={error} />
      {busy && <p role="status" className="text-sm text-muted">…</p>}
      {preview && (
        <div className="space-y-2" aria-label={t("ts.preview")}>
          {preview.files.map((f) => (
            <div key={f.filename} className="rounded-sm border border-hairline p-2 text-sm">
              <strong>{f.filename}</strong>
              {f.error && <div role="alert" className="note note--danger mt-1">{f.error}</div>}
              {f.certificates.map((c) => (
                <details key={c.fingerprint_sha256} className="mt-1">
                  <summary className="cursor-pointer">{c.subject} <RoleBadge role={c.role} /> {c.duplicate && <Badge>{t("ts.duplicate")}</Badge>} {c.error && <Badge tone="danger">{t("ts.invalid")}</Badge>}</summary>
                  {c.error && <div role="alert" className="note note--danger my-1">{c.error}</div>}
                  <CertDetail cert={c} />
                </details>
              ))}
            </div>
          ))}
          {!preview.valid && <Note tone="warning">{t("ts.invalid")}</Note>}
        </div>
      )}
    </div>
  );
}

function CreateDialog({ onClose, onDone }: { onClose: () => void; onDone: (s: TrustStoreDetail) => void }) {
  const { t } = useI18n();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [files, setFiles] = useState<PickedFile[]>([]);
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  async function submit() {
    if (!files.length) { setError(new Error(t("ts.noFile"))); return; }
    setBusy(true);
    try { onDone(await api<TrustStoreDetail>("/admin/trust-stores", { method: "POST", body: { name, description, files } })); } catch (e) { setError(e); } finally { setBusy(false); }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={t("ts.new")} wide>
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("col.name")}><Input value={name} maxLength={120} onChange={(e) => setName(e.target.value)} placeholder="Client A — PKI interne" /></Field>
          <Field label={t("col.description")}><Input value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
        </div>
        <ImportPicker onFiles={setFiles} />
        <ErrorNote error={error} />
        <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>{t("action.cancel")}</Button><Button disabled={!name.trim() || !files.length || busy} onClick={() => void submit()}><Upload />{t("ts.create")}</Button></div>
      </div>
    </Dialog>
  );
}

function StoreDialog({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { t, locale } = useI18n();
  const { data, reload, error } = useLoad(() => api<TrustStoreDetail>(`/admin/trust-stores/${id}`), [id]);
  const [err, setErr] = useState<unknown>();
  const [files, setFiles] = useState<PickedFile[]>([]);
  const [mode, setMode] = useState<"current" | "empty">("current");
  const [comment, setComment] = useState("");
  const [pickerKey, setPickerKey] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  const [viewVersion, setViewVersion] = useState<number | null>(null);
  const { data: old } = useLoad(() => (viewVersion ? api<{ certificates: TrustCert[] }>(`/admin/trust-stores/${id}/versions/${viewVersion}`) : Promise.resolve(undefined)), [id, viewVersion]);
  const act = async (fn: () => Promise<unknown>) => { try { await fn(); setErr(undefined); await reload(); onChanged(); } catch (e) { setErr(e); } };
  if (!data) return <Dialog open onOpenChange={(o) => !o && onClose()} title="…" wide><ErrorNote error={error} /></Dialog>;
  const certs = viewVersion && old ? old.certificates : data.certificates;
  const readOnly = viewVersion !== null && viewVersion !== data.version;
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={data.name} wide>
      <div className="space-y-4">
        <ErrorNote error={err ?? error} />
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Badge tone={data.active ? "success" : "neutral"}>{data.active ? t("sched.active") : t("sched.inactive")}</Badge>
          <Badge tone="primary">v{data.version}</Badge>
          <span className="text-muted">{data.description}</span>
          <span className="ml-auto font-mono text-xs text-muted" title={data.content_sha256 ?? ""}>SHA-256 {short(data.content_sha256 ?? "")}</span>
        </div>
        <Note tone="info">{t("ts.intermediateHint")}</Note>
        <Table><thead><tr><Th>{t("ts.subject")}</Th><Th>{t("ts.type")}</Th><Th>{t("ts.validity")}</Th><Th /></tr></thead>
          <tbody>{certs.map((c) => (
            <tr key={c.fingerprint_sha256}>
              <Td className="max-w-md break-words text-xs">{c.subject}{open === c.fingerprint_sha256 && <div className="mt-2"><CertDetail cert={c} onRemove={!readOnly ? () => { if (window.confirm(t("ts.confirmRemove"))) void act(() => api(`/admin/trust-stores/${id}/versions`, { method: "POST", body: { remove: [c.fingerprint_sha256], comment: "remove" } })); } : undefined} /></div>}</Td>
              <Td><RoleBadge role={c.role} /></Td>
              <Td className="whitespace-nowrap text-xs">{c.expired ? <Badge tone="danger">{t("ts.expired")}</Badge> : <>{formatDate(c.not_after, locale)}{c.expires_in_days < 60 && <Badge tone="warning" className="ml-1">{t("ts.expiresIn", { days: c.expires_in_days })}</Badge>}</>}</Td>
              <Td><Button size="sm" variant="outline" onClick={() => setOpen(open === c.fingerprint_sha256 ? null : c.fingerprint_sha256)}>{t("ts.details")}</Button></Td>
            </tr>))}</tbody></Table>

        <section className="space-y-3"><h3 className="font-medium">{t("ts.publish")}</h3>
          <ImportPicker key={pickerKey} onFiles={setFiles} />
          <div className="flex flex-wrap items-end gap-3">
            <Field label={t("ts.version")}><Select value={mode} onChange={(e) => setMode(e.target.value as "current" | "empty")}><option value="current">{t("ts.modeAdd")}</option><option value="empty">{t("ts.modeReplace")}</option></Select></Field>
            <Field label={t("ts.comment")}><Input value={comment} maxLength={500} onChange={(e) => setComment(e.target.value)} /></Field>
            <Button disabled={!files.length} onClick={() => { if (window.confirm(t("ts.confirmPublish"))) void act(async () => { await api(`/admin/trust-stores/${id}/versions`, { method: "POST", body: { files, base: mode, comment } }); setFiles([]); setComment(""); setPickerKey((k) => k + 1); setViewVersion(null); }); }}><Plus />{t("ts.publish")}</Button>
          </div>
        </section>

        <section><h3 className="mb-1 font-medium">{t("ts.versions")}</h3>
          <Table><thead><tr><Th>{t("ts.version")}</Th><Th>{t("col.date")}</Th><Th>{t("ts.certs")}</Th><Th>{t("ts.comment")}</Th><Th /></tr></thead>
            <tbody>{data.versions.map((v) => <tr key={v.id}><Td>v{v.version}</Td><Td className="text-xs">{formatDate(v.created_at, locale)}</Td><Td className="text-xs">{v.anchor_count} + {v.intermediate_count}</Td><Td className="text-xs">{v.comment}</Td>
              <Td><Button size="sm" variant="outline" onClick={() => setViewVersion(v.version === data.version ? null : v.version)}>{t("ts.details")}</Button></Td></tr>)}</tbody></Table></section>

        <section><h3 className="mb-1 font-medium">{t("ts.profiles")}</h3>
          {data.profiles.length ? <ul className="list-disc pl-5 text-sm">{data.profiles.map((p) => <li key={p.id}>{p.name} <span className="text-muted">(v{p.versions.join(", v")})</span></li>)}</ul> : <p className="text-sm text-muted">{t("ts.noProfile")}</p>}
          {data.run_count > 0 && <p className="mt-1 text-sm text-muted">{t("ts.scansUsing", { n: data.run_count })}</p>}
        </section>

        <div className="flex flex-wrap justify-between gap-2">
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => { if (!data.active || window.confirm(t("ts.confirmDeactivate"))) void act(() => api(`/admin/trust-stores/${id}`, { method: "PUT", body: { active: !data.active } })); }}>{data.active ? t("admin.disable") : t("admin.enable")}</Button>
            {!data.profiles.length && data.run_count === 0 && <Button variant="danger" onClick={() => { if (window.confirm(t("ts.confirmDelete"))) void act(async () => { await api(`/admin/trust-stores/${id}`, { method: "DELETE" }); onClose(); }); }}>{t("ts.delete")}</Button>}
          </div>
          <Button onClick={onClose}>{t("action.close")}</Button>
        </div>
      </div>
    </Dialog>
  );
}

export function TrustStoresTab() {
  const { t, locale } = useI18n();
  const { data, reload, error } = useLoad(() => api<TrustStoreSummary[]>("/admin/trust-stores"));
  const [creating, setCreating] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const privateStores = data?.filter((s) => !s.builtin) ?? [];
  return (
    <>
      <div className="my-3 flex items-center justify-between gap-3"><p className="text-sm text-muted">{t("ts.subtitle")}</p><Button onClick={() => setCreating(true)}><Plus />{t("ts.new")}</Button></div>
      <ErrorNote error={error} />
      <Card>{data ? (
        <Table><thead><tr><Th>{t("col.name")}</Th><Th>{t("col.description")}</Th><Th>{t("ts.certs")}</Th><Th>{t("ts.type")}</Th><Th>{t("col.status")}</Th><Th>{t("ts.updated")}</Th><Th /></tr></thead>
          <tbody>{data.map((s) => (
            <tr key={s.id}>
              <Td className="font-medium"><ShieldCheck className="mr-1 inline size-4 text-primary" aria-hidden />{s.name}{s.version && <span className="ml-2 text-xs font-normal text-muted">v{s.version}</span>}</Td>
              <Td className="text-xs text-muted">{s.builtin ? t("ts.builtinHint") : s.description}</Td>
              <Td>{s.certificate_count}{s.has_expired && <Badge tone="danger" className="ml-2" title={t("ts.hasExpired")}>{t("ts.expired")}</Badge>}</Td>
              <Td><Badge tone={s.builtin ? "info" : "primary"}>{s.builtin ? t("ts.builtin") : t("ts.private")}</Badge></Td>
              <Td><Badge tone={s.active ? "success" : "neutral"}>{s.active ? t("sched.active") : t("sched.inactive")}</Badge></Td>
              <Td className="whitespace-nowrap text-xs">{s.updated_at ? formatDate(s.updated_at, locale) : "—"}</Td>
              <Td>{!s.builtin && <div className="flex justify-end"><Button size="sm" variant="outline" onClick={() => setOpenId(s.id)}>{t("ts.details")}</Button></div>}</Td>
            </tr>))}</tbody></Table>
      ) : <Empty>…</Empty>}
        {data && !privateStores.length && <div className="border-t border-hairline p-4 text-sm text-muted">{t("ts.empty")}</div>}
      </Card>
      {creating && <CreateDialog onClose={() => setCreating(false)} onDone={(s) => { setCreating(false); setOpenId(s.id); void reload(); }} />}
      {openId && <StoreDialog id={openId} onClose={() => { setOpenId(null); void reload(); }} onChanged={() => void reload()} />}
    </>
  );
}
