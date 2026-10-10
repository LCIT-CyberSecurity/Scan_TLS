import { useEffect, useState, type FormEvent } from "react";
import { LockKeyhole, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { ErrorNote } from "../components/common";
import { useI18n, LOCALES } from "../i18n";
import "../styles/login.css";

/** Sign-in, laid out like LCIT Sign: introduction panel on the left, sign-in card on the right.
 *  Also handles the forced password change (e.g. the deployment default password). */
export default function Login() {
  const { user, login, refresh } = useAuth();
  const { t, locale, setLocale } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState<unknown>();
  const [sso, setSso] = useState(false);
  const [crashtest, setCrashtest] = useState(false);
  const mustChange = !!user?.must_change_password;

  useEffect(() => { api<{ sso: { enabled: boolean }; crashtest?: boolean }>("/auth/providers").then((p) => { setSso(p.sso.enabled); setCrashtest(!!p.crashtest); }).catch(() => undefined); }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(undefined);
    try {
      if (mustChange) { await api("/auth/password", { method: "POST", body: { current_password: password, new_password: next } }); await refresh(); }
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
              {mustChange ? (
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
              )}
              <ErrorNote error={error} />
              <button type="submit" className="login-submit">{mustChange ? t("login.changeAndContinue") : t("login.submit")}</button>
              {sso && !mustChange && <button type="button" className="login-sso" onClick={() => { window.location.href = "/api/auth/sso/login"; }}>{t("login.sso")}</button>}
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
