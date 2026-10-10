import { useState } from "react";
import { api } from "../api/client";
import type { Role, User } from "../api/types";
import { Empty, ErrorNote, PageHeader, useLoad } from "../components/common";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Dialog } from "../components/ui/dialog";
import { Field, Input, Select } from "../components/ui/input";
import { Table, Td, Th } from "../components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useI18n } from "../i18n";
import { formatDate } from "../lib/utils";

const ROLES: Role[] = ["AUDITOR", "USER", "OPERATOR", "ADMIN"];

function Users() {
  const { t, locale } = useI18n();
  const { data, reload, error } = useLoad(() => api<User[]>("/admin/users"));
  const [form, setForm] = useState({ email: "", display_name: "", role: "USER" as Role });
  const [secret, setSecret] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>();
  const run = async (fn: () => Promise<void>) => { try { await fn(); setErr(undefined); await reload(); } catch (e) { setErr(e); } };
  return (
    <>
      <ErrorNote error={error ?? err} />
      <Card className="my-4 p-4"><div className="flex flex-wrap items-end gap-3">
        <Field label="E-mail"><Input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
        <Field label={t("col.name")}><Input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
        <Field label={t("admin.role")}><Select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</Select></Field>
        <Button disabled={!form.email} onClick={() => void run(async () => { const r = await api<{ temporary_password: string }>("/admin/users", { method: "POST", body: form }); setSecret(r.temporary_password); setForm({ email: "", display_name: "", role: "USER" }); })}>{t("admin.createUser")}</Button>
      </div></Card>
      <Card>{data?.length ? (
        <Table><thead><tr><Th>E-mail</Th><Th>{t("admin.role")}</Th><Th>{t("admin.source")}</Th><Th>{t("admin.lastLogin")}</Th><Th>{t("col.status")}</Th><Th /></tr></thead>
          <tbody>{data.map((u) => (
            <tr key={u.id}><Td className="font-medium">{u.email}<div className="text-xs font-normal text-muted">{u.display_name}</div></Td>
              <Td><Select aria-label={t("admin.role")} className="h-8 w-36" value={u.role} onChange={(e) => void run(async () => { await api(`/admin/users/${u.id}`, { method: "PUT", body: { role: e.target.value } }); })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</Select></Td>
              <Td>{u.local_account ? "local" : "SSO"}</Td><Td>{formatDate(u.last_login_at, locale)}</Td>
              <Td><Badge tone={u.active ? "success" : "neutral"}>{u.active ? t("sched.active") : t("sched.inactive")}</Badge></Td>
              <Td><div className="flex justify-end gap-2">
                <Button size="sm" variant="outline" onClick={() => void run(async () => { await api(`/admin/users/${u.id}`, { method: "PUT", body: { role: u.role, active: !u.active } }); })}>{u.active ? t("admin.disable") : t("admin.enable")}</Button>
                {u.local_account && <Button size="sm" variant="outline" onClick={() => void run(async () => { if (window.confirm(t("admin.confirmReset"))) setSecret((await api<{ temporary_password: string }>(`/admin/users/${u.id}/reset-password`, { method: "POST" })).temporary_password); })}>{t("admin.resetPassword")}</Button>}
              </div></Td></tr>
          ))}</tbody></Table>
      ) : <Empty>—</Empty>}</Card>
      {secret && <Dialog open onOpenChange={() => setSecret(null)} title={t("admin.tempPassword")}><p className="mb-3 text-sm text-muted">{t("admin.tempPasswordHint")}</p><code className="block break-all rounded-sm bg-surface-2 p-3 text-sm">{secret}</code><div className="mt-4 flex justify-end"><Button onClick={() => setSecret(null)}>{t("action.close")}</Button></div></Dialog>}
    </>
  );
}

interface AuditRow { id: string; created_at: string; actor: string; action: string; resource_type: string; resource_id: string; outcome: string; detail: unknown }
function Audit() {
  const { t, locale } = useI18n();
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const { data, error } = useLoad(() => api<AuditRow[]>("/admin/audit", { params: { action, actor, limit: "300" } }), [action, actor]);
  return (
    <>
      <div className="mb-3 flex gap-3"><Input aria-label="Action" placeholder="action (e.g. auth.)" className="w-56" value={action} onChange={(e) => setAction(e.target.value)} /><Input aria-label="Actor" placeholder={t("admin.actor")} className="w-56" value={actor} onChange={(e) => setActor(e.target.value)} /></div>
      <ErrorNote error={error} />
      <Card>{data?.length ? <Table><thead><tr><Th>{t("col.date")}</Th><Th>{t("admin.actor")}</Th><Th>Action</Th><Th>{t("admin.resource")}</Th><Th>{t("admin.outcome")}</Th></tr></thead>
        <tbody>{data.map((e) => <tr key={e.id}><Td className="whitespace-nowrap">{formatDate(e.created_at, locale)}</Td><Td>{e.actor}</Td><Td className="font-mono text-xs">{e.action}</Td><Td className="text-xs">{e.resource_type} {e.resource_id.slice(0, 8)}</Td><Td><Badge tone={e.outcome === "success" ? "success" : "danger"}>{e.outcome}</Badge></Td></tr>)}</tbody></Table> : <Empty>—</Empty>}</Card>
    </>
  );
}

interface Smtp { host: string; port: number; starttls: boolean; username: string; from: string }
interface Graph { tenant_id: string; client_id: string; sender: string }
interface Settings { retention: { reports_days: number; runs_days: number; audit_days: number }; notifications: { connector: string; smtp: Smtp; graph?: Graph } }
interface Step { step: string; status: string; detail: string }
function SettingsTab() {
  const { t } = useI18n();
  const { data, reload } = useLoad(() => api<Settings>("/admin/settings"));
  const [ret, setRet] = useState<Settings["retention"] | null>(null);
  const [smtp, setSmtp] = useState<Smtp | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [connector, setConnector] = useState<string | null>(null);
  const [steps, setSteps] = useState<Step[]>([]);
  const [to, setTo] = useState("");
  const [err, setErr] = useState<unknown>();
  const [saved, setSaved] = useState("");
  const retention = ret ?? data?.retention;
  const smtpCfg = smtp ?? data?.notifications.smtp;
  const graphCfg = graph ?? data?.notifications.graph ?? { tenant_id: "", client_id: "", sender: "" };
  const conn = connector ?? data?.notifications.connector ?? "none";
  const save = async (key: string, value: unknown) => { try { await api(`/admin/settings/${key}`, { method: "PUT", body: { value } }); setSaved(key); setErr(undefined); await reload(); } catch (e) { setErr(e); } };
  return (
    <div className="grid max-w-3xl gap-6">
      <ErrorNote error={err} />
      {retention && (
        <Card><CardHeader><CardTitle>{t("admin.retention")}</CardTitle></CardHeader><CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-3">
            {(["reports_days", "runs_days", "audit_days"] as const).map((k) => <Field key={k} label={t(`admin.${k}` as never)}><Input type="number" min={1} value={retention[k]} onChange={(e) => setRet({ ...retention, [k]: Number(e.target.value) })} /></Field>)}
          </div>
          <Button onClick={() => void save("retention", retention)}>{t("action.save")}</Button>
        </CardContent></Card>
      )}
      {smtpCfg && (
        <Card><CardHeader><CardTitle>{t("admin.connector")}</CardTitle></CardHeader><CardContent className="space-y-4">
          <Field label={t("admin.connector")}><Select value={conn} onChange={(e) => setConnector(e.target.value)}><option value="none">{t("admin.connectorNone")}</option><option value="smtp">SMTP</option><option value="graph">Microsoft Graph</option></Select></Field>
          {conn === "smtp" && (
            <>
              <p className="text-xs text-muted">{t("admin.smtpPasswordHint")}</p>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Host"><Input value={smtpCfg.host} onChange={(e) => setSmtp({ ...smtpCfg, host: e.target.value })} /></Field>
                <Field label="Port"><Input type="number" value={smtpCfg.port} onChange={(e) => setSmtp({ ...smtpCfg, port: Number(e.target.value) })} /></Field>
                <Field label={t("admin.smtpUser")}><Input value={smtpCfg.username} onChange={(e) => setSmtp({ ...smtpCfg, username: e.target.value })} /></Field>
                <Field label={t("admin.smtpFrom")}><Input value={smtpCfg.from} onChange={(e) => setSmtp({ ...smtpCfg, from: e.target.value })} /></Field>
              </div>
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={smtpCfg.starttls} onChange={(e) => setSmtp({ ...smtpCfg, starttls: e.target.checked })} />STARTTLS</label>
            </>
          )}
          {conn === "graph" && (
            <>
              <p className="text-xs text-muted">{t("admin.graphSecretHint")}</p>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label={t("admin.graphTenant")}><Input value={graphCfg.tenant_id} onChange={(e) => setGraph({ ...graphCfg, tenant_id: e.target.value })} /></Field>
                <Field label={t("admin.graphClient")}><Input value={graphCfg.client_id} onChange={(e) => setGraph({ ...graphCfg, client_id: e.target.value })} /></Field>
                <Field label={t("admin.graphSender")}><Input type="email" value={graphCfg.sender} onChange={(e) => setGraph({ ...graphCfg, sender: e.target.value })} /></Field>
              </div>
            </>
          )}
          <div className="flex flex-wrap items-end gap-3">
            <Button onClick={() => void save("notifications", { connector: conn, smtp: smtpCfg, graph: graphCfg })}>{t("action.save")}</Button>
            {conn !== "none" && <>
              <Field label={t("admin.testTo")}><Input type="email" value={to} onChange={(e) => setTo(e.target.value)} /></Field>
              <Button variant="outline" onClick={async () => { try { setSteps(await api<Step[]>("/admin/notifications/test", { method: "POST", body: { to: to || null } })); setErr(undefined); } catch (e) { setErr(e); } }}>{t("admin.testConnector")}</Button>
            </>}
          </div>
          {steps.map((s) => <div key={s.step} className={`rounded-sm border px-3 py-2 text-sm ${s.status === "ok" ? "border-success-line bg-success-soft text-success" : "border-danger-line bg-danger-soft text-danger"}`}><b>{s.step}</b> — {s.status}{s.detail && `: ${s.detail}`}</div>)}
        </CardContent></Card>
      )}
      {saved && <p className="text-sm text-success">{t("admin.saved")}</p>}
    </div>
  );
}

function Diagnostics() {
  const { t } = useI18n();
  const { data, error } = useLoad(() => api<Record<string, unknown>>("/admin/diagnostics"), [], 15000);
  const failed = useLoad(() => api<{ id: string; name: string; status: string; error: string }[]>("/admin/failed-runs"));
  const yes = (v: unknown) => <Badge tone={v ? "success" : "danger"}>{v ? "OK" : "KO"}</Badge>;
  return (
    <div className="grid gap-6">
      <ErrorNote error={error} />
      {data && <Card><CardHeader><CardTitle>{t("admin.diagnostics")}</CardTitle></CardHeader><CardContent className="grid gap-3 text-sm sm:grid-cols-2">
        <div>PostgreSQL {yes(data.database)}</div><div>nmap {yes(data.nmap)}</div><div>openssl {yes(data.openssl)}</div><div>SSO {yes(data.sso_configured)}</div>
        <div>{t("admin.activeRuns")}: <b>{String(data.active_runs)}</b></div><div>{t("admin.storageFree")}: <b>{String(data.storage_free_gb ?? "?")} GB</b></div>
        <div className="sm:col-span-2 text-muted">{t("admin.limits")}: {JSON.stringify(data.limits)}</div>
      </CardContent></Card>}
      <Card><CardHeader><CardTitle>{t("admin.failedRuns")}</CardTitle></CardHeader>
        {failed.data?.length ? <Table><thead><tr><Th>{t("col.name")}</Th><Th>{t("col.status")}</Th><Th>{t("admin.error")}</Th></tr></thead><tbody>{failed.data.map((r) => <tr key={r.id}><Td>{r.name}</Td><Td>{r.status}</Td><Td className="max-w-md break-words text-xs text-danger">{r.error}</Td></tr>)}</tbody></Table> : <Empty>—</Empty>}
      </Card>
    </div>
  );
}

export default function Admin() {
  const { t } = useI18n();
  return (
    <>
      <PageHeader title={t("nav.admin")} />
      <Tabs defaultValue="users">
        <TabsList><TabsTrigger value="users">{t("admin.users")}</TabsTrigger><TabsTrigger value="audit">{t("admin.audit")}</TabsTrigger><TabsTrigger value="settings">{t("admin.settings")}</TabsTrigger><TabsTrigger value="diag">{t("admin.diagnostics")}</TabsTrigger></TabsList>
        <TabsContent value="users"><Users /></TabsContent>
        <TabsContent value="audit"><Audit /></TabsContent>
        <TabsContent value="settings"><SettingsTab /></TabsContent>
        <TabsContent value="diag"><Diagnostics /></TabsContent>
      </Tabs>
    </>
  );
}
