import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { ErrorNote } from "../components/common";
import { Button } from "../components/ui/button";
import { Field, Input } from "../components/ui/input";
import { useI18n, LOCALES } from "../i18n";

export default function Login() {
  const { user, login, refresh } = useAuth();
  const { t, locale, setLocale } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState<unknown>();
  const [sso, setSso] = useState(false);
  const mustChange = !!user?.must_change_password;

  useEffect(() => { api<{ sso: { enabled: boolean } }>("/auth/providers").then((p) => setSso(p.sso.enabled)).catch(() => undefined); }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(undefined);
    try {
      if (mustChange) { await api("/auth/password", { method: "POST", body: { current_password: password, new_password: next } }); await refresh(); }
      else await login(username, password);
    } catch (err) { setError(err instanceof ApiError && err.status === 401 ? new Error(t("login.invalid")) : err); }
  }

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-xl border border-border bg-surface p-7 shadow-md">
        <div className="flex items-center gap-3"><img src="/lcit-mark.png" alt="" className="size-9" /><h1 className="text-xl">TLS Scan</h1></div>
        {mustChange ? (
          <>
            <p className="rounded-sm border border-warning-line bg-warning-soft px-3 py-2 text-sm text-warning">{t("login.mustChange")}</p>
            <Field label={t("login.currentPassword")}><Input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></Field>
            <Field label={t("login.newPassword")} hint={t("login.passwordHint")}><Input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required minLength={12} /></Field>
          </>
        ) : (
          <>
            <Field label={t("login.username")}><Input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus /></Field>
            <Field label={t("login.password")}><Input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></Field>
          </>
        )}
        <ErrorNote error={error} />
        <Button type="submit" className="w-full">{mustChange ? t("login.changeAndContinue") : t("login.submit")}</Button>
        {sso && !mustChange && <Button type="button" variant="outline" className="w-full" onClick={() => { window.location.href = "/api/auth/sso/login"; }}>{t("login.sso")}</Button>}
        <div className="flex justify-center gap-3 pt-1 text-xs text-muted">
          {LOCALES.map((l) => <button type="button" key={l} onClick={() => setLocale(l)} className={l === locale ? "font-semibold text-primary" : "hover:text-fg"}>{l.toUpperCase()}</button>)}
        </div>
      </form>
    </div>
  );
}
