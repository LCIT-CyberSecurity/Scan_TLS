import { useEffect, useState, type FormEvent } from "react";
import { LockKeyhole, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { ErrorNote } from "../components/common";
import { useI18n, LOCALES } from "../i18n";
import "../styles/login.css";

interface Providers { sso: { enabled: boolean; provider?: string }; ldap: { enabled: boolean; name?: string } }
const ssoLabel = (provider: string | undefined, t: (k: never) => string) => t((provider === "entra" ? "login.ssoMicrosoft" : provider === "google" ? "login.ssoGoogle" : "login.sso") as never);
const MicrosoftMark = () => <svg width="18" height="18" viewBox="0 0 21 21" aria-hidden="true" style={{ marginRight: 10 }}><rect width="10" height="10" fill="#f25022" /><rect x="11" width="10" height="10" fill="#7fba00" /><rect y="11" width="10" height="10" fill="#00a4ef" /><rect x="11" y="11" width="10" height="10" fill="#ffb900" /></svg>;
const GoogleMark = () => <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true" style={{ marginRight: 10 }}><path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9.1 3.6l6.8-6.8C35.8 2.4 30.2 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.1C12.4 13.6 17.7 9.5 24 9.5z" /><path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.5 5.8c4.4-4.1 7.1-10.1 7.1-17.5z" /><path fill="#FBBC05" d="M10.5 28.7c-.5-1.5-.8-3-.8-4.7s.3-3.2.8-4.7l-7.9-6.1C.9 16.4 0 20.1 0 24s.9 7.6 2.6 10.8l7.9-6.1z" /><path fill="#34A853" d="M24 48c6.2 0 11.4-2 15.2-5.5l-7.5-5.8c-2.1 1.4-4.7 2.3-7.7 2.3-6.3 0-11.6-4.1-13.5-9.8l-7.9 6.1C6.5 42.6 14.6 48 24 48z" /></svg>;

/** Sign-in, laid out like LCIT Sign: introduction panel on the left, sign-in card on the right.
 *  Also handles the forced password change (e.g. the deployment default password). */
export default function Login() {
  const { user, login, refresh } = useAuth();
  const { t, locale, setLocale } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState<unknown>();
  const [providers, setProviders] = useState<Providers | null>(null);   // null until known: no form flashes then disappears
  const [showLocal, setShowLocal] = useState(false);
  const [crashtest, setCrashtest] = useState(false);
  const mustChange = !!user?.must_change_password;

  useEffect(() => { api<Providers & { crashtest?: boolean }>("/auth/providers").then((p) => { setProviders(p); setCrashtest(!!p.crashtest); }).catch(() => setProviders({ sso: { enabled: false }, ldap: { enabled: false } })); }, []);
  const sso = providers?.sso.enabled ? providers.sso : null;
  const ldap = providers?.ldap.enabled ? providers.ldap : null;
  const external = !!(sso || ldap) && !mustChange;
  const localVisible = !!providers && (!external || showLocal);
  const ldapVisible = !!ldap && !mustChange && !showLocal;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(undefined);
    try {
      if (mustChange) { await api("/auth/password", { method: "POST", body: { current_password: password, new_password: next } }); await refresh(); }
      else if (ldapVisible) { await api("/auth/ldap/login", { method: "POST", body: { username, password } }); await refresh(); }
      else await login(username, password);
    } catch (err) { setError(err instanceof ApiError && err.status === 401 ? new Error(t("login.invalid")) : err); }
  }

  return (
    <div className="login-page">
      <div className="auth-layout">
        <aside className="auth-intro">
          <div className="auth-product">
            <span className="auth-product-icon"><ShieldCheck size={22} strokeWidth={1.8} aria-hidden="true" /></span>
            <span><strong>TLS SCAN</strong><small>{t("login.product")}</small></span>
          </div>
          <div className="auth-message"><h2>{t("login.tagline")}</h2></div>
          <div className="auth-foot">{t("login.vendor")} <strong>LCIT Cybersecurity</strong></div>
        </aside>

        <main className="auth-form-wrap">
          <div className="auth-form-content">
            <div className="auth-company">
              <img src="/lcit-logo.png" alt="LCIT" width={100} height={76} />
              <div><strong>LCIT Cybersecurity</strong><span>{t("login.space")}</span></div>
            </div>

            <form className="login-card" onSubmit={submit}>
              <span className="auth-eyebrow">{t("login.eyebrow")}</span>
              <h1>{mustChange ? t("login.changeTitle") : t("login.title")}</h1>
              <p>{mustChange ? t("login.mustChange") : t("login.intro")}</p>
              {crashtest && <p className="login-notice">{t("login.crashtest")}</p>}
              {!providers && <p className="hint" role="status">…</p>}
              {sso && !mustChange && !showLocal && <button type="button" className="login-sso login-sso--primary" onClick={() => { window.location.href = "/api/auth/sso/login"; }}>{sso.provider === "entra" ? <MicrosoftMark /> : sso.provider === "google" ? <GoogleMark /> : null}{ssoLabel(sso.provider, t)}</button>}
              {ldapVisible && <p className="hint">{t("login.directory")}</p>}
              {(localVisible || ldapVisible) && (mustChange ? (
                <>
                  <label>{t("login.currentPassword")}<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
                  <label>{t("login.newPassword")}<input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required minLength={12} /></label>
                  <span className="hint">{t("login.passwordHint")}</span>
                </>
              ) : (
                <>
                  <label>{t("login.username")}<input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus /></label>
                  <label>{t("login.password")}<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
                </>
              ))}
              <ErrorNote error={error} />
              {(localVisible || ldapVisible) && <button type="submit" className="login-submit">{mustChange ? t("login.changeAndContinue") : t("login.submit")}</button>}
              {external && <button type="button" className="login-local-toggle" onClick={() => { setShowLocal((v) => !v); setError(undefined); }}>{showLocal ? t("login.backToExternal") : t("login.local")}</button>}
              <div className="login-lang">
                {LOCALES.map((l) => <button type="button" key={l} onClick={() => setLocale(l)} aria-current={l === locale}>{l.toUpperCase()}</button>)}
              </div>
            </form>

            <p className="auth-form-foot"><LockKeyhole size={12} aria-hidden="true" /> {t("login.foot")}</p>
          </div>
        </main>
      </div>
    </div>
  );
}
