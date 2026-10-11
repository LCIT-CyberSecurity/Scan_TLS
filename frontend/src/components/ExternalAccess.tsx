import { Copy, KeyRound } from "lucide-react";
import { useState } from "react";
import { api } from "../api/client";
import type { AccessKey, AccessService, MyAccess } from "../api/types";
import { useI18n } from "../i18n";
import { formatDate } from "../lib/utils";
import { ErrorNote, Note, useLoad } from "./common";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Dialog } from "./ui/dialog";

export const SERVICES: AccessService[] = ["api", "mcp"];

/** The secret is shown once, in its own dialog. */
export function KeyDialog({ secret, onClose }: { secret: string; onClose: () => void }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const copy = async () => { try { await navigator.clipboard.writeText(secret); setCopied(true); } catch { setCopied(false); } };
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={t("access.keyTitle")}>
      <Note tone="warning">{t("access.keyWarning")}</Note>
      <code className="mt-3 block break-all rounded-sm bg-surface-2 p-3 text-sm" data-testid="secret">{secret}</code>
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="outline" onClick={() => void copy()}><Copy />{copied ? t("access.copied") : t("access.copy")}</Button>
        <Button onClick={onClose}>{t("action.close")}</Button>
      </div>
    </Dialog>
  );
}

export function keyBadge(key: AccessKey, t: ReturnType<typeof useI18n>["t"]) {
  return key.active ? <Badge tone="success">{t("access.keyActive")}</Badge> : <Badge>{t("access.keyNone")}</Badge>;
}

/** One service (REST API or MCP) of the signed-in user: global state, individual authorisation, key. */
export function ServiceAccess({ service, state, onGenerate, onRevoke }: { service: AccessService; state: MyAccess[AccessService]; onGenerate: () => void; onRevoke: () => void }) {
  const { t, locale } = useI18n();
  const usable = state.global_enabled && state.allowed;
  const origin = typeof window === "undefined" ? "https://tls-scan.example" : window.location.origin;
  return (
    <Card><CardHeader><CardTitle>{t(`access.${service}.title` as never)}</CardTitle></CardHeader><CardContent className="space-y-4">
      <p className="text-sm text-muted">{t(`access.${service}.about` as never)}</p>
      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
        <div><dt className="text-muted">{t("access.global")}</dt><dd><Badge tone={state.global_enabled ? "success" : "neutral"}>{state.global_enabled ? t("access.enabled") : t("access.disabled")}</Badge></dd></div>
        <div><dt className="text-muted">{t("access.individual")}</dt><dd><Badge tone={state.allowed ? "success" : "neutral"}>{state.allowed ? t("access.allowed") : t("access.notAllowed")}</Badge></dd></div>
        <div><dt className="text-muted">{t("access.key")}</dt><dd>{keyBadge(state.key, t)} {state.key.prefix && <code className="text-xs">{state.key.prefix}…</code>}</dd></div>
        <div><dt className="text-muted">{t("access.expires")}</dt><dd>{state.key.expires_at ? formatDate(state.key.expires_at, locale) : "—"}</dd></div>
        <div><dt className="text-muted">{t("access.lastUsed")}</dt><dd>{state.key.last_used_at ? formatDate(state.key.last_used_at, locale) : "—"}</dd></div>
      </dl>
      {!state.allowed && <Note tone="info">{t("access.askAdmin")}</Note>}
      {state.allowed && !state.global_enabled && <Note tone="info">{t("access.serviceOff")}</Note>}
      <div className="flex flex-wrap gap-2">
        <Button disabled={!usable} onClick={onGenerate}><KeyRound />{state.key.active ? t("access.regenerate") : t("access.generate")}</Button>
        {state.key.active && <Button variant="outline" onClick={onRevoke}>{t("access.revoke")}</Button>}
      </div>
      <details className="text-sm"><summary className="cursor-pointer">{t("access.howTo")}</summary>
        <pre className="mt-2 overflow-x-auto rounded-sm bg-surface-2 p-3 text-xs">{service === "api"
          ? `curl -H "Authorization: Bearer tls_scan_pat_…" ${origin}/api/v1/scans\n${t("access.docsAt")} ${origin}/api/v1/docs`
          : `${t("access.mcpUrl")} ${origin}/mcp\nAuthorization: Bearer tls_scan_mcp_…`}</pre></details>
    </CardContent></Card>
  );
}

/** Preferences section "API and MCP access". */
export function ExternalAccessSection() {
  const { t } = useI18n();
  const { data, reload, error } = useLoad(() => api<MyAccess>("/me/access"));
  const [secret, setSecret] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>();
  const generate = (service: AccessService) => async () => {
    try { const r = await api<{ token: string }>(`/me/access/${service}/token`, { method: "POST" }); setSecret(r.token); setErr(undefined); await reload(); } catch (e) { setErr(e); }
  };
  const revoke = (service: AccessService) => async () => {
    if (!window.confirm(t("access.confirmRevoke"))) return;
    try { await api(`/me/access/${service}/token`, { method: "DELETE" }); setErr(undefined); await reload(); } catch (e) { setErr(e); }
  };
  return (
    <section aria-labelledby="access-title" className="grid gap-4">
      <h2 id="access-title" className="text-lg font-semibold">{t("access.section")}</h2>
      <ErrorNote error={error ?? err} />
      {data && SERVICES.map((s) => <ServiceAccess key={s} service={s} state={data[s]} onGenerate={() => void generate(s)()} onRevoke={() => void revoke(s)()} />)}
      {secret && <KeyDialog secret={secret} onClose={() => setSecret(null)} />}
    </section>
  );
}

/** Administration: the two global switches. */
export function ExternalAccessSwitches({ state, onToggle }: { state: { api_enabled: boolean; mcp_enabled: boolean }; onToggle: (service: AccessService, enabled: boolean) => void }) {
  const { t } = useI18n();
  return (
    <Card><CardHeader><CardTitle>{t("access.adminTitle")}</CardTitle></CardHeader><CardContent className="space-y-3">
      <Note tone="info">{t("access.adminHint")}</Note>
      {SERVICES.map((s) => {
        const on = state[`${s}_enabled`];
        return (
          <label key={s} className="flex items-center justify-between gap-4 rounded-sm border border-border p-3 text-sm">
            <span><strong>{t(`access.${s}.title` as never)}</strong><span className="block text-muted">{t(`access.${s}.switchHint` as never)}</span></span>
            <span className="flex items-center gap-2"><Badge tone={on ? "success" : "neutral"}>{on ? t("access.enabled") : t("access.disabled")}</Badge>
              <input type="checkbox" role="switch" aria-label={t(`access.${s}.title` as never)} checked={on} onChange={(e) => onToggle(s, e.target.checked)} /></span>
          </label>
        );
      })}
    </CardContent></Card>
  );
}
