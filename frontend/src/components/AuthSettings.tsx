import { useState } from "react";
import { api } from "../api/client";
import { ErrorNote, Note, useLoad } from "./common";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Field, Input, Select, Textarea } from "./ui/input";
import { useI18n } from "../i18n";
import { formatDate } from "../lib/utils";

type Provider = "" | "none" | "entra" | "google" | "ldap";
interface AuthValue {
  provider: Provider; default_role: string | null; auto_provision: boolean | null;
  entra: { tenant_id: string; client_id: string; issuer: string };
  google: { client_id: string; allowed_domains: string[] };
  ldap: Record<string, string | boolean>;
}
interface AuthData {
  stored: AuthValue; redirect_uri: string;
  effective: { provider: string; source: string; issuer: string; client_id: string; default_role: string; auto_provision: boolean; complete: boolean };
  secrets: { oidc_client_secret: boolean; google_client_secret: boolean; ldap_bind_password: boolean };
  environment: { oidc_configured: boolean; oidc_provider: string; auto_provision: boolean | null };
}
interface TestStep { step: string; status: "ok" | "fail" | "warn" | "info"; detail: string }
interface Diag { at: string; action: string; who: string; outcome: string; ip: string; reason: string; code: string; explanation: string }
const TONE = { ok: "success", fail: "danger", warn: "warning", info: "info" } as const;
const LDAP_TEXT = ["name", "server_url", "base_dn", "login_attribute", "user_filter", "bind_dn", "email_attribute", "name_attribute", "id_attribute"] as const;

function SecretState({ ok, variable }: { ok: boolean; variable: string }) {
  const { t } = useI18n();
  return <p className="text-xs text-muted"><Badge tone={ok ? "success" : "danger"}>{ok ? t("auth.secretSet") : t("auth.secretMissing")}</Badge> {t("auth.secretHint", { variable })}</p>;
}

/** Administration -> Authentication: the active external sign-in, its non-secret settings, a step-by-step test, and the latest failures. */
export function AuthSettings() {
  const { t, locale } = useI18n();
  const tr = t as unknown as (k: string, v?: Record<string, string | number>) => string;
  const { data, reload, error } = useLoad(() => api<AuthData>("/admin/auth"));
  const diag = useLoad(() => api<Diag[]>("/admin/auth/diagnostics"));
  const [draft, setDraft] = useState<AuthValue | null>(null);
  const [steps, setSteps] = useState<TestStep[]>([]);
  const [login, setLogin] = useState({ username: "", password: "" });
  const [err, setErr] = useState<unknown>();
  const [saved, setSaved] = useState(false);
  if (!data) return <ErrorNote error={error} />;
  const v = draft ?? data.stored;
  const set = (patch: Partial<AuthValue>) => { setDraft({ ...v, ...patch }); setSaved(false); };
  const run = async (fn: () => Promise<void>) => { try { await fn(); setErr(undefined); } catch (e) { setErr(e); } };
  const activeLabel = data.effective.provider ? tr(`auth.p.${data.effective.provider}`) : t("auth.p.local");
  const testable = v.provider === "entra" || v.provider === "google" || v.provider === "ldap" ? v.provider : data.effective.provider === "generic" ? "generic" : "";
  const setL = (k: string, val: string | boolean) => set({ ldap: { ...v.ldap, [k]: val } });

  return (
    <div className="grid max-w-3xl gap-6">
      <ErrorNote error={err ?? error} />
      <Card><CardHeader><CardTitle>{t("auth.title")}</CardTitle></CardHeader><CardContent className="space-y-4">
        <p className="text-xs text-muted">{t("auth.intro")}</p>
        <p className="text-sm" aria-label={t("auth.active")}>{t("auth.active")}: <Badge tone={data.effective.provider ? "primary" : "neutral"}>{activeLabel}</Badge>{" "}
          <span className="text-xs text-muted">{data.effective.provider ? tr(`auth.src.${data.effective.source}`) : ""}</span> · {t("auth.localAlways")}</p>

        <Field label={t("auth.provider")}>
          <Select value={v.provider} onChange={(e) => set({ provider: e.target.value as Provider })}>
            {data.environment.oidc_configured && <option value="">{t("auth.p.env")}</option>}
            <option value="none">{t("auth.p.local")}</option>
            <option value="entra">{t("auth.p.entra")}</option>
            <option value="google">{t("auth.p.google")}</option>
            <option value="ldap">{t("auth.p.ldap")}</option>
          </Select></Field>
        {v.provider === "" && !data.environment.oidc_configured && <Note>{t("auth.noneHint")}</Note>}

        {(v.provider === "entra" || v.provider === "google") && (
          <Note>{t("auth.redirectHint")} <code className="break-all">{data.redirect_uri}</code></Note>)}

        {v.provider === "entra" && (
          <div className="space-y-4">
            <p className="text-xs text-muted">{t("auth.entraHint")}</p>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("auth.tenant")} hint={t("auth.tenantHint")}><Input value={v.entra.tenant_id} onChange={(e) => set({ entra: { ...v.entra, tenant_id: e.target.value } })} /></Field>
              <Field label={t("auth.clientId")}><Input value={v.entra.client_id} onChange={(e) => set({ entra: { ...v.entra, client_id: e.target.value } })} /></Field>
              <Field label={t("auth.issuer")} hint={t("auth.issuerHint")}><Input value={v.entra.issuer} onChange={(e) => set({ entra: { ...v.entra, issuer: e.target.value } })} /></Field>
            </div>
            <SecretState ok={data.secrets.oidc_client_secret} variable="TLS_SCAN_OIDC_CLIENT_SECRET" />
          </div>)}

        {v.provider === "google" && (
          <div className="space-y-4">
            <p className="text-xs text-muted">{t("auth.googleHint")}</p>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("auth.clientId")}><Input value={v.google.client_id} onChange={(e) => set({ google: { ...v.google, client_id: e.target.value } })} /></Field>
              <Field label={t("auth.domains")} hint={t("auth.domainsHint")}><Textarea rows={3} value={v.google.allowed_domains.join("\n")} onChange={(e) => set({ google: { ...v.google, allowed_domains: e.target.value.split(/[\s,;]+/).filter(Boolean) } })} /></Field>
            </div>
            <SecretState ok={data.secrets.google_client_secret} variable="TLS_SCAN_GOOGLE_CLIENT_SECRET" />
          </div>)}

        {v.provider === "ldap" && (
          <div className="space-y-4">
            <p className="text-xs text-muted">{t("auth.ldapHint")}</p>
            <div className="grid gap-4 sm:grid-cols-2">
              {LDAP_TEXT.map((k) => <Field key={k} label={tr(`auth.ldap.${k}`)}><Input value={String(v.ldap[k] ?? "")} onChange={(e) => setL(k, e.target.value)} /></Field>)}
            </div>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={!!v.ldap.starttls} onChange={(e) => setL("starttls", e.target.checked)} />{t("auth.ldap.starttls")}</label>
            <Field label={t("auth.ldap.ca")} hint={t("auth.ldap.caHint")}><Textarea rows={4} value={String(v.ldap.ca_pem ?? "")} onChange={(e) => setL("ca_pem", e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" /></Field>
            <SecretState ok={data.secrets.ldap_bind_password} variable="TLS_SCAN_LDAP_BIND_PASSWORD" />
          </div>)}

        {(v.provider === "entra" || v.provider === "google" || v.provider === "ldap") && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("auth.autoProvision")} hint={t("auth.autoProvisionHint")}>
              <Select value={v.auto_provision === null ? (data.effective.auto_provision ? "true" : "false") : String(v.auto_provision)} onChange={(e) => set({ auto_provision: e.target.value === "true" })}>
                <option value="false">{t("auth.autoOff")}</option><option value="true">{t("auth.autoOn")}</option></Select></Field>
            <Field label={t("auth.defaultRole")} hint={t("auth.defaultRoleHint")}>
              <Select value={v.default_role ?? data.effective.default_role} onChange={(e) => set({ default_role: e.target.value })}>{["AUDITOR", "USER", "OPERATOR"].map((r) => <option key={r}>{r}</option>)}</Select></Field>
          </div>)}

        <div className="flex flex-wrap gap-3">
          <Button onClick={() => void run(async () => { await api("/admin/auth", { method: "PUT", body: { value: v } }); setDraft(null); setSaved(true); await reload(); await diag.reload(); })}>{t("action.save")}</Button>
          {testable && <Button variant="outline" onClick={() => void run(async () => { setSteps(await api<TestStep[]>(`/admin/auth/test/${testable}`, { method: "POST", body: {} })); await diag.reload(); })}>{t("auth.test")}</Button>}
          {saved && <span className="self-center text-sm text-success">{t("admin.saved")}</span>}
        </div>
        {draft && <p className="text-xs text-muted">{t("auth.unsaved")}</p>}

        {v.provider === "ldap" && (
          <fieldset className="rounded border border-border p-3"><legend className="px-1 text-sm font-medium">{t("auth.userTest")}</legend>
            <p className="mb-2 text-xs text-muted">{t("auth.userTestHint")}</p>
            <div className="flex flex-wrap items-end gap-3">
              <Field label={t("login.username")}><Input autoComplete="off" value={login.username} onChange={(e) => setLogin({ ...login, username: e.target.value })} /></Field>
              <Field label={t("login.password")}><Input type="password" autoComplete="new-password" value={login.password} onChange={(e) => setLogin({ ...login, password: e.target.value })} /></Field>
              <Button variant="outline" disabled={!login.username || !login.password} onClick={() => void run(async () => { setSteps(await api<TestStep[]>("/admin/auth/test/ldap", { method: "POST", body: login })); setLogin({ username: "", password: "" }); await diag.reload(); })}>{t("auth.userTestRun")}</Button>
            </div></fieldset>)}

        {steps.length > 0 && (
          <ul className="space-y-1" aria-label={t("auth.test")}>{steps.map((s) => (
            <li key={s.step}><Note tone={s.status === "ok" ? "success" : s.status === "fail" ? "danger" : s.status === "warn" ? "warning" : "info"}><b>{s.step}</b> — <Badge tone={TONE[s.status]}>{tr(`auth.st.${s.status}`)}</Badge>{s.detail && <span className="block text-xs">{s.detail}</span>}</Note></li>))}</ul>)}
      </CardContent></Card>

      <Card><CardHeader><CardTitle>{t("auth.diag")}</CardTitle></CardHeader><CardContent>
        {diag.data?.length ? (
          <ul className="space-y-2 text-sm">{diag.data.map((d, i) => (
            <li key={i} className="border-b border-hairline pb-2"><span className="text-xs text-muted">{formatDate(d.at, locale)} · {d.action} · {d.who || "—"} · {d.ip}</span>
              <div><Badge tone="danger">{d.code}</Badge> {d.explanation}</div></li>))}</ul>
        ) : <p className="text-sm text-muted">{t("auth.diagNone")}</p>}
      </CardContent></Card>
    </div>
  );
}
