import { useEffect, useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { ErrorNote } from "../components/common";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Field, Input, Select, Textarea } from "../components/ui/input";
import { useI18n } from "../i18n";

type Evidence = { id: string; target_id: string; protocol: "tls" | "ipsec" | "ssh"; port: number; sni: string; state: "unknown" | "internet_confirmed" | "not_internet_confirmed"; zone_context: string; evidence_method: string; source: string; justification: string; confidence: string; validated: boolean };
type ExposureForm = Omit<Evidence, "id" | "target_id">;
const empty: ExposureForm = { protocol: "tls", port: 443, sni: "", state: "unknown", zone_context: "unknown", evidence_method: "", source: "", justification: "", confidence: "unknown", validated: false };
export function EndpointExposureEditor({ targetId }: { targetId: string }) {
  const { t } = useI18n();
  const { user, atLeast } = useAuth();
  const [items, setItems] = useState<Evidence[]>([]);
  const [form, setForm] = useState<ExposureForm>({ ...empty });
  const [editing, setEditing] = useState<string>();
  const [error, setError] = useState<unknown>();
  const load = async () => { try { setItems(await api<Evidence[]>(`/targets/${targetId}/exposures`)); } catch (e) { setError(e); } };
  useEffect(() => { void load(); }, [targetId]);
  function edit(item: Evidence) { setEditing(item.id); setForm({ protocol: item.protocol, port: item.port, sni: item.sni, state: item.state, zone_context: item.zone_context,
    evidence_method: item.evidence_method, source: item.source, justification: item.justification, confidence: item.confidence, validated: item.validated }); }
  async function save() { try { setError(undefined); await api(editing ? `/targets/${targetId}/exposures/${editing}` : `/targets/${targetId}/exposures`, { method: editing ? "PUT" : "POST", body: form }); setEditing(undefined); setForm({ ...empty }); await load(); } catch (e) { setError(e); } }
  if (!atLeast("OPERATOR")) return null;
  return <Card className="space-y-3 p-4">
    <div><h3 className="font-semibold">{t("exposure.title")}</h3><p className="text-xs text-muted">{t("exposure.hint")}</p></div>
    {items.length > 0 && <ul className="space-y-2">{items.map((item) => <li key={item.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-border p-2 text-sm"><span><strong>{item.protocol.toUpperCase()}:{item.port}</strong>{item.sni ? ` · SNI ${item.sni}` : ""} · {t(`exposure.${item.validated ? item.state : "unverified"}` as never)} <Badge tone={item.validated ? "success" : "warning"}>{item.validated ? t("exposure.validated") : t("exposure.pending")}</Badge><small className="block text-muted">{item.source || t("exposure.noEvidence")}{item.justification ? ` · ${item.justification}` : ""}</small></span><Button size="sm" variant="outline" disabled={item.validated && user?.role !== "ADMIN"} onClick={() => edit(item)}>{t("action.edit")}</Button></li>)}</ul>}
    <div className="grid gap-3 sm:grid-cols-3">
      <Field label={t("exposure.protocol")}><Select value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value as Evidence["protocol"], port: e.target.value === "ipsec" ? 500 : e.target.value === "ssh" ? 22 : 443 })}><option value="tls">TLS</option><option value="ipsec">IPsec / IKE</option><option value="ssh">SSH</option></Select></Field>
      <Field label={t("exposure.port")}><Input type="number" min={1} max={65535} value={form.port} onChange={(e) => setForm({ ...form, port: Number(e.target.value) })} /></Field>
      <Field label={t("exposure.sni")}><Input value={form.sni} onChange={(e) => setForm({ ...form, sni: e.target.value })} /></Field>
      <Field label={t("exposure.state")}><Select value={form.state} onChange={(e) => setForm({ ...form, state: e.target.value as Evidence["state"] })}><option value="unknown">{t("exposure.unknown")}</option><option value="internet_confirmed">{t("exposure.internet_confirmed")}</option><option value="not_internet_confirmed">{t("exposure.not_internet_confirmed")}</option></Select></Field>
      <Field label={t("exposure.zone")}><Select value={form.zone_context} onChange={(e) => setForm({ ...form, zone_context: e.target.value })}>{["unknown", "dmz", "internal_wide", "segmented"].map((v) => <option key={v} value={v}>{t(`exposure.zone.${v}` as never)}</option>)}</Select></Field>
      <Field label={t("exposure.confidence")}><Select value={form.confidence} onChange={(e) => setForm({ ...form, confidence: e.target.value })}>{["unknown", "low", "medium", "high"].map((v) => <option key={v} value={v}>{t(`exposure.confidence.${v}` as never)}</option>)}</Select></Field>
      <Field label={t("exposure.method")}><Select value={form.evidence_method} onChange={(e) => setForm({ ...form, evidence_method: e.target.value })}><option value="">—</option>{["admin_attested", "external_probe", "network_rule_review", "other"].map((v) => <option key={v} value={v}>{t(`exposure.method.${v}` as never)}</option>)}</Select></Field>
      <Field label={t("exposure.source")}><Input maxLength={255} value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} /></Field>
      <Field label={t("exposure.justification")}><Textarea rows={2} maxLength={2000} value={form.justification} onChange={(e) => setForm({ ...form, justification: e.target.value })} /></Field>
    </div>
    {atLeast("ADMIN") && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.validated} onChange={(e) => setForm({ ...form, validated: e.target.checked })} />{t("exposure.validate")}</label>}
    <p className="text-xs text-muted">{t("exposure.noInference")}</p><ErrorNote error={error} />
    <div className="flex gap-2"><Button onClick={() => void save()}>{editing ? t("action.save") : t("exposure.add")}</Button>{editing && <Button variant="outline" onClick={() => { setEditing(undefined); setForm({ ...empty }); }}>{t("action.cancel")}</Button>}</div>
  </Card>;
}
