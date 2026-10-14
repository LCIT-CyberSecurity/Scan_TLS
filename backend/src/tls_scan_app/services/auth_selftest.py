"""'Test the configuration' for each external sign-in: technical checks, each with an actionable explanation.

These steps prove the PLUMBING (configuration, network, discovery document, signing keys, directory bind). Only a real
interactive sign-in proves that a person can enter: the last OIDC step says so instead of pretending otherwise.
Nothing here ever returns or logs a secret.
"""
from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlparse

import httpx
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException

from tls_scan_app.auth.diagnostics import explain
from tls_scan_app.config import Settings
from tls_scan_app.connectors import ldap_auth
from tls_scan_app.connectors.base import Step
from tls_scan_app.services import auth_config
from tls_scan_app.services.logs import scrub_text


def _is_https(url: str) -> bool:
    p = urlparse(url)
    return p.scheme == "https" or (p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1"))


def oidc_steps(cfg: auth_config.Effective, redirect_uri: str, public_base_url: str) -> list[Step]:
    steps: list[Step] = []
    missing = [name for name, ok in (("client ID", bool(cfg.client_id)), ("issuer", bool(cfg.issuer))) if not ok]
    if cfg.provider == "entra" and not cfg.tenant_id and cfg.source == "database":
        missing.append("tenant ID")
    if cfg.provider == "google" and not cfg.allowed_domains:
        missing.append("allowed Workspace domain")
    steps.append(Step("configuration", "fail" if missing else "ok", f"Missing: {', '.join(missing)}." if missing else f"Provider {cfg.provider}, client {cfg.client_id[:8]}…"))
    if missing:
        return steps
    steps.append(Step("client secret", "ok" if cfg.client_secret else "fail",
                      "Set in the server environment." if cfg.client_secret else "No client secret: set TLS_SCAN_OIDC_CLIENT_SECRET (Entra / generic) or TLS_SCAN_GOOGLE_CLIENT_SECRET (Google), or the matching *_FILE variable."))
    if cfg.provider == "entra" and cfg.source == "database" and any(p in ("common", "organizations", "consumers") for p in cfg.issuer.lower().split("/")):
        steps.append(Step("tenant restriction", "fail", "The issuer is a multi-tenant endpoint: it would accept accounts from other tenants. Use your tenant ID."))
    else:
        steps.append(Step("tenant restriction", "ok", f"Restricted to tenant {cfg.tenant_id}." if cfg.tenant_id else (f"Restricted to Workspace domain(s): {', '.join(cfg.allowed_domains)}." if cfg.allowed_domains else "Issuer only (no tenant or domain restriction configured).")))
    steps.append(Step("redirect URI", "ok" if _is_https(redirect_uri) else "warn", f"Register exactly: {redirect_uri}" + ("" if _is_https(redirect_uri) else " (not https: most providers refuse it; set TLS_SCAN_PUBLIC_BASE_URL to the https address)")))
    try:
        r = httpx.get(cfg.issuer.rstrip("/") + "/.well-known/openid-configuration", timeout=10)
    except httpx.HTTPError as error:
        steps.append(Step("issuer reachable", "fail", f"{explain('discovery')['explanation']} ({type(error).__name__})"))
        return steps
    if r.status_code != 200:
        steps.append(Step("issuer reachable", "fail", f"The OpenID configuration answered HTTP {r.status_code}. Check the issuer URL (tenant ID)."))
        return steps
    doc: dict[str, Any] = r.json()
    steps.append(Step("issuer reachable", "ok", "OpenID configuration document retrieved."))
    problems = [k for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri") if not doc.get(k)]
    insecure = [k for k in ("authorization_endpoint", "token_endpoint", "jwks_uri") if doc.get(k) and not _is_https(doc[k])]
    if problems or insecure:
        steps.append(Step("document coherence", "fail", f"Missing {problems}" if problems else f"Not https: {insecure}"))
    elif cfg.source == "database" and cfg.provider == "entra" and "{tenantid}" in str(doc["issuer"]):
        steps.append(Step("document coherence", "fail", "The document is the multi-tenant one: the issuer must contain your tenant ID."))
    else:
        steps.append(Step("document coherence", "ok", f"Issuer {doc['issuer']}"))
    try:
        j = httpx.get(doc["jwks_uri"], timeout=10)
        keys = j.json().get("keys", []) if j.status_code == 200 else []
        steps.append(Step("signing keys (JWKS)", "ok" if keys else "fail", f"{len(keys)} key(s)." if keys else explain("jwks")["explanation"]))
    except (httpx.HTTPError, ValueError, KeyError) as error:
        steps.append(Step("signing keys (JWKS)", "fail", f"{explain('jwks')['explanation']} ({type(error).__name__})"))
    steps.append(Step("interactive sign-in", "info", "These checks do not prove that a person can sign in: use the sign-in button with a test account (and a second account outside the tenant / domain, which must be refused)."))
    return steps


def ldap_steps(cfg: auth_config.Effective, username: str = "", password: str = "") -> list[Step]:
    c = cfg.ldap
    steps: list[Step] = []
    if not (c.get("server_url") and c.get("base_dn")):
        return [Step("configuration", "fail", "The LDAP URL and the base DN are required.")]
    steps.append(Step("configuration", "ok", f"{c['server_url']} · base {c['base_dn']} · login attribute {c.get('login_attribute')}"))
    try:
        ldap_auth.require_secure(c)
        steps.append(Step("transport security", "ok", "ldaps://" if str(c["server_url"]).lower().startswith("ldaps") else "StartTLS (certificate validated)"))
    except ldap_auth.LdapAuthError as error:
        steps.append(Step("transport security", "fail", error.message))
        return steps
    url = urlparse(c["server_url"])
    port = url.port or (636 if url.scheme == "ldaps" else 389)
    try:
        socket.getaddrinfo(url.hostname, port)
        steps.append(Step("DNS", "ok", url.hostname or ""))
    except OSError as error:
        steps.append(Step("DNS", "fail", f"Cannot resolve the server: {error}"))
        return steps
    if c.get("bind_dn") and not cfg.ldap_password:
        steps.append(Step("service account bind", "fail", explain("ldap_service_bind")["explanation"]))
        return steps
    try:
        socket.create_connection((url.hostname, port), timeout=8).close()
        steps.append(Step("TCP connection", "ok", f"{url.hostname}:{port}"))
    except OSError as error:
        steps.append(Step("TCP connection", "fail", f"{explain('ldap_unreachable')['explanation']} ({type(error).__name__})"))
        return steps
    bind_dn = c.get("bind_dn") or None
    try:
        conn = ldap_auth._open(c, bind_dn, cfg.ldap_password or None)   # noqa: SLF001 - same connection code as the sign-in itself
        steps.append(Step("TLS / certificate", "ok", "Certificate validated" + (" with the configured CA." if c.get("ca_pem") else " with the system trust store.")))
        try:
            ok = conn.bind()
        finally:
            pass
        steps.append(Step("service account bind", "ok" if ok else "fail", "Bound as the service account." if ok else explain("ldap_service_bind")["explanation"]))
        if not ok:
            conn.unbind()
            return steps
    except ldap_auth.LdapAuthError as error:
        steps.append(Step("TLS / certificate" if error.code == "ldap_tls" else "service account bind", "fail", explain(error.code)["explanation"]))
        return steps
    except LDAPException as error:
        steps.append(Step("service account bind", "fail", explain("ldap_service_bind")["explanation"] + f" ({type(error).__name__})"))
        return steps
    try:
        conn.search(c["base_dn"], "(objectClass=*)", SUBTREE, size_limit=1, attributes=[])
        res = (conn.result or {}).get("description")
        steps.append(Step("base DN", "ok" if res in ("success", "sizeLimitExceeded") else "fail", c["base_dn"] if res in ("success", "sizeLimitExceeded") else explain("ldap_base_dn")["explanation"]))
        if res not in ("success", "sizeLimitExceeded"):
            return steps
        conn.search(c["base_dn"], f"(&{c['user_filter']}({c['login_attribute']}=*))", SUBTREE, attributes=[c["login_attribute"]], size_limit=3, time_limit=10)
        found = len([e for e in conn.response or [] if e.get("type") == "searchResEntry"])
        steps.append(Step("user search", "ok" if found else "warn", f"{found}+ account(s) visible with the user filter." if found else "The filter matches no account: check the user filter and the login attribute."))
    except LDAPException as error:
        steps.append(Step("user search", "fail", f"{explain('ldap_filter')['explanation']} ({type(error).__name__})"))
    finally:
        conn.unbind()
    if username and password:   # only when the administrator explicitly asks for it; the password is used once and never kept
        try:
            who = ldap_auth.authenticate(c, cfg.ldap_password, username, password)
            steps.append(Step("user authentication", "ok", f"{who.login} authenticated" + ("" if who.email else " (no e-mail attribute: sign-in would be refused)")))
        except ldap_auth.LdapAuthError as error:
            steps.append(Step("user authentication", "fail", explain(error.code)["explanation"]))
    else:
        steps.append(Step("user authentication", "info", "Not tested: enter a test login and password to verify a real sign-in."))
    return steps


def run(db, settings: Settings, provider: str, redirect_uri: str, body: dict[str, Any]) -> list[dict[str, str]]:
    cfg = auth_config.effective(db, settings)
    if provider in ("entra", "google", "generic") and cfg.provider != provider:
        return [Step("configuration", "fail", f"{provider} is not the active provider. Save and activate it, then test.").as_dict()]
    if provider == "ldap" and cfg.provider != "ldap":
        return [Step("configuration", "fail", "LDAP is not the active provider (or its URL / base DN are missing). Save and activate it, then test.").as_dict()]
    steps = ldap_steps(cfg, str(body.get("username", "")), str(body.get("password", ""))) if provider == "ldap" else oidc_steps(cfg, redirect_uri, settings.public_base_url)
    return [{**s.as_dict(), "detail": scrub_text(s.detail)} for s in steps]
