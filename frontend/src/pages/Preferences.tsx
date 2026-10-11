import { useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { ErrorNote, PageHeader } from "../components/common";
import { ExternalAccessSection } from "../components/ExternalAccess";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Field, Input, Select } from "../components/ui/input";
import { LOCALES, useI18n, type Locale } from "../i18n";
import { APPEARANCES, THEMES, applyAppearance, applyTheme, readAppearance, readTheme, type Appearance, type ThemeId } from "../theme";

const EVENTS = ["scan_completed", "scan_failed", "scan_cancelled", "new_noncompliance", "certificate_expiring", "schedule_problem"] as const;

export default function Preferences() {
  const { t, locale, setLocale } = useI18n();
  const { user, refresh } = useAuth();
  const [theme, setTheme] = useState<ThemeId>(readTheme());
  const [appearance, setAppearance] = useState<Appearance>(readAppearance());
  const [pw, setPw] = useState({ current_password: "", new_password: "" });
  const [msg, setMsg] = useState("");
  const [error, setError] = useState<unknown>();
  const events = user?.notify_events ?? [...EVENTS];

  const patch = async (body: Record<string, unknown>) => { try { await api("/auth/preferences", { method: "PATCH", body }); await refresh(); setError(undefined); } catch (e) { setError(e); } };
  return (
    <>
      <PageHeader title={t("nav.preferences")} />
      <ErrorNote error={error} />
      <div className="grid max-w-3xl gap-6">
        <Card><CardHeader><CardTitle>{t("pref.display")}</CardTitle></CardHeader><CardContent className="grid gap-4 sm:grid-cols-3">
          <Field label={t("pref.language")}><Select value={locale} onChange={(e) => { setLocale(e.target.value as Locale); void patch({ locale: e.target.value }); }}>{LOCALES.map((l) => <option key={l} value={l}>{{ fr: "Français", en: "English", de: "Deutsch" }[l]}</option>)}</Select></Field>
          <Field label={t("pref.appearance")}><Select value={appearance} onChange={(e) => { const v = e.target.value as Appearance; setAppearance(v); applyAppearance(v); void patch({ theme: v }); }}>{APPEARANCES.map((a) => <option key={a} value={a}>{t(`pref.${a}` as never)}</option>)}</Select></Field>
          <Field label={t("pref.palette")}><Select value={theme} onChange={(e) => { const v = e.target.value as ThemeId; setTheme(v); applyTheme(v); void patch({ palette: v }); }}>{THEMES.map((x) => <option key={x} value={x}>{x}</option>)}</Select></Field>
        </CardContent></Card>
        <Card><CardHeader><CardTitle>{t("pref.notifications")}</CardTitle></CardHeader><CardContent className="space-y-2">
          {EVENTS.map((ev) => <label key={ev} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={events.includes(ev)} onChange={(e) => void patch({ notify_events: e.target.checked ? [...events, ev] : events.filter((x) => x !== ev) })} />{t(`pref.ev.${ev}` as never)}</label>)}
        </CardContent></Card>
        <ExternalAccessSection />
        {user?.local_account && (
          <Card><CardHeader><CardTitle>{t("pref.password")}</CardTitle></CardHeader><CardContent className="space-y-4">
            <Field label={t("login.currentPassword")}><Input type="password" autoComplete="current-password" value={pw.current_password} onChange={(e) => setPw({ ...pw, current_password: e.target.value })} /></Field>
            <Field label={t("login.newPassword")} hint={t("login.passwordHint")}><Input type="password" autoComplete="new-password" value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.target.value })} /></Field>
            {msg && <p className="text-sm text-success">{msg}</p>}
            <Button onClick={async () => { try { await api("/auth/password", { method: "POST", body: pw }); setPw({ current_password: "", new_password: "" }); setMsg(t("pref.passwordChanged")); setError(undefined); } catch (e) { setMsg(""); setError(e); } }}>{t("action.save")}</Button>
          </CardContent></Card>
        )}
      </div>
    </>
  );
}
