import { useEffect, useState, type FormEvent } from "react";
import { LockKeyhole, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { PRODUCT_NAME } from "../brand";
import { ErrorNote } from "../components/common";
import { useI18n, LOCALES } from "../i18n";
import "../styles/login.css";

interface Providers { local?: boolean; sso: { enabled: boolean; provider?: string }; ldap: { enabled: boolean; name?: string } }
type CredentialMethod = "ldap" | "local";

/** Sign-in, laid out like LCIT Sign: introduction panel on the left, sign-in card on the right.
 * Also handles the forced password change (e.g. the deployment default password). */
export default function Login() {
  const { user, login, refresh } = useAuth();
  const { t, locale, setLocale } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState<unknown>();
  const [providers, setProviders] = useState<Providers | null>(null);
  const [credentialMethod, setCredentialMethod] = useState<CredentialMethod | null>(null);
  const [crashtest, setCrashtest] = useState(false);
  const mustChange = !!user?.must_change_password;

  useEffect(() => {
    if (new URLSearchParams(window.location.search).has("auth_error")) {
      setError(new Error(t("login.ssoError")));
      window.history.replaceState({}, "", window.location.pathname);
    }
    api<Providers & { crashtest?: boolean }>("/auth/providers")
      .then((p) => { setProviders(p); setCrashtest(!!p.crashtest); })
      .catch(() => {
        // Keep the local recovery path available when public provider discovery is unavailable.
        setProviders({ local: true, sso: { enabled: false }, ldap: { enabled: false } });
        setError(new Error(t("login.providersError")));
      });
  }, [t]);

  const ssoEnabled = !!providers?.sso.enabled;
  const ldapEnabled = !!providers?.ldap.enabled;
  const localAvailable = !!providers && providers.local !== false;
  const hasCredentials = ldapEnabled || localAvailable;
  const primaryMethod: CredentialMethod = ldapEnabled ? "ldap" : "local";
  const selectedMethod = credentialMethod ?? primaryMethod;
  const credentialAvailable = selectedMethod === "ldap" ? ldapEnabled : localAvailable;

  async function submit(e: FormEvent, method: CredentialMethod) {
    e.preventDefault();
    setError(undefined);
    try {
      if (mustChange) {
        await api("/auth/password", { method: "POST", body: { current_password: password, new_password: next } });
        await refresh();
      } else if (method === "ldap") {
        await api("/auth/ldap/login", { method: "POST", body: { username, password } });
        await refresh();
      } else await login(username, password);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? new Error(t("login.invalid")) : err);
    }
  }

  function credentials(method: CredentialMethod, autofocus = false) {
    return <form className="login-credentials" onSubmit={(event) => void submit(event, method)}>
      {method === "ldap" && <p className="hint">{t("login.directory")}</p>}
      <label>{t("login.username")}<input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus={autofocus} /></label>
      <label>{t("login.password")}<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
      <button type="submit" className="login-submit">{t("login.submit")}</button>
    </form>;
  }

  return (
    <div className="login-page">
      <div className="auth-layout">
        <aside className="auth-intro">
          <div className="auth-product">
            <span className="auth-product-icon"><ShieldCheck size={22} strokeWidth={1.8} aria-hidden="true" /></span>
            <span><strong>{PRODUCT_NAME.toUpperCase()}</strong><small>{t("login.product")}</small></span>
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

            <section className="login-card">
              <span className="auth-eyebrow">{t("login.eyebrow")}</span>
              <h1>{mustChange ? t("login.changeTitle") : t("login.title")}</h1>
              <p>{mustChange ? t("login.mustChange") : t("login.intro")}</p>
              {crashtest && <p className="login-notice">{t("login.crashtest")}</p>}
              {!providers && <p className="hint" role="status">{t("login.loadingMethods")}</p>}
              <ErrorNote error={error} />

              {ssoEnabled && !mustChange && <a className="button button--primary login-sso--primary" href="/api/auth/sso/login">{t("login.submit")}</a>}

              {mustChange && <form className="login-credentials" onSubmit={(event) => void submit(event, primaryMethod)}>
                <label>{t("login.currentPassword")}<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required autoFocus /></label>
                <label>{t("login.newPassword")}<input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required minLength={12} /></label>
                <span className="hint">{t("login.passwordHint")}</span>
                <button type="submit" className="login-submit">{t("login.changeAndContinue")}</button>
              </form>}

              {!mustChange && providers && ssoEnabled && hasCredentials && <details className="login-methods">
                <summary>{t("login.otherMethods")}</summary>
                {ldapEnabled && localAvailable && <fieldset className="login-method-choice">
                  <legend>{t("login.chooseMethod")}</legend>
                  <label><input type="radio" name="credential-method" value="ldap" checked={selectedMethod === "ldap"} onChange={() => setCredentialMethod("ldap")} />{t("login.directorySignIn")}</label>
                  <label><input type="radio" name="credential-method" value="local" checked={selectedMethod === "local"} onChange={() => setCredentialMethod("local")} />{t("login.localSignIn")}</label>
                </fieldset>}
                {credentialAvailable && credentials(selectedMethod)}
              </details>}

              {!mustChange && providers && !ssoEnabled && hasCredentials && <>
                {credentials(primaryMethod, true)}
                {primaryMethod === "ldap" && localAvailable && <details className="login-methods login-methods--fallback">
                  <summary>{t("login.localSignIn")}</summary>
                  {credentials("local")}
                </details>}
              </>}
              {!mustChange && providers && !ssoEnabled && !hasCredentials && <p className="login-empty-methods" role="status">{t("login.noMethods")}</p>}

              <div className="login-lang">
                {LOCALES.map((l) => <button type="button" key={l} onClick={() => setLocale(l)} aria-current={l === locale}>{l.toUpperCase()}</button>)}
              </div>
            </section>

            <p className="auth-form-foot"><LockKeyhole size={12} aria-hidden="true" /> {t("login.foot")}</p>
          </div>
        </main>
      </div>
    </div>
  );
}
