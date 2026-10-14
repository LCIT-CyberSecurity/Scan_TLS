"""Which external sign-in is active, and with what settings.

One external provider at a time (Entra ID or Google Workspace through OIDC, or a directory through LDAP), plus the
local accounts, which always work. Priority rule, applied here only:

1. `system_settings.auth` (Administration -> Authentication) when it names a provider;
2. otherwise the legacy environment (`TLS_SCAN_OIDC_*`), which keeps working untouched after an update;
3. `provider = "none"` switches the external sign-in off even when the environment still describes one.

Secrets never live in the database: the Entra / generic client secret is `TLS_SCAN_OIDC_CLIENT_SECRET`, the Google one
`TLS_SCAN_GOOGLE_CLIENT_SECRET`, the LDAP service password `TLS_SCAN_LDAP_BIND_PASSWORD` (each also as `*_FILE`).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session as DbSession

from tls_scan_app.config import Settings
from tls_scan_app.models import SystemSetting

PROVIDERS = ("", "none", "entra", "google", "ldap")
FORBIDDEN_TENANTS = {"common", "organizations", "consumers"}   # multi-tenant endpoints: never a single-tenant restriction
ROLES = ("AUDITOR", "USER", "OPERATOR")                         # an external identity never starts above OPERATOR, never ADMIN
GOOGLE_ISSUER = "https://accounts.google.com"
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
DEFAULT_LDAP = {"name": "", "server_url": "", "base_dn": "", "login_attribute": "uid", "user_filter": "(objectClass=person)", "bind_dn": "",
                "starttls": False, "ca_pem": "", "email_attribute": "mail", "name_attribute": "cn", "id_attribute": "entryUUID"}
DEFAULT_STORED: dict[str, Any] = {
    "provider": "", "entra": {"tenant_id": "", "client_id": "", "issuer": ""}, "google": {"client_id": "", "allowed_domains": []},
    "ldap": dict(DEFAULT_LDAP), "default_role": None, "auto_provision": None,
}


@dataclass
class Effective:
    provider: str = ""            # "" (local only) | entra | google | generic | ldap
    source: str = "none"          # none | database | environment
    issuer: str = ""
    client_id: str = ""
    client_secret: str = field(default="", repr=False)
    tenant_id: str = ""
    allowed_domains: list[str] = field(default_factory=list)
    ldap: dict[str, Any] = field(default_factory=dict)
    ldap_password: str = field(default="", repr=False)
    default_role: str = "USER"
    auto_provision: bool = False

    @property
    def oidc(self) -> bool:
        return self.provider in ("entra", "google", "generic") and bool(self.issuer and self.client_id)

    @property
    def ldap_enabled(self) -> bool:
        return self.provider == "ldap" and bool(self.ldap.get("server_url") and self.ldap.get("base_dn"))


def stored(db: DbSession) -> dict[str, Any]:
    row = db.get(SystemSetting, "auth")
    value = dict(row.value) if row and isinstance(row.value, dict) else {}
    out: dict[str, Any] = {**DEFAULT_STORED, **{k: v for k, v in value.items() if k in DEFAULT_STORED}}
    for key in ("entra", "google", "ldap"):
        out[key] = {**DEFAULT_STORED[key], **(value.get(key) if isinstance(value.get(key), dict) else {})}
    return out


def entra_issuer(tenant_id: str, login_url: str) -> str:
    return f"{login_url.rstrip('/')}/{tenant_id}/v2.0"


def effective(db: DbSession, settings: Settings) -> Effective:
    cfg = stored(db)
    provider = cfg["provider"] or ""
    role = cfg["default_role"] or settings.oidc_default_role
    auto = cfg["auto_provision"] if isinstance(cfg["auto_provision"], bool) else bool(settings.sso_auto_provision)
    base = Effective(default_role=role, auto_provision=auto)
    if provider == "entra" and cfg["entra"].get("tenant_id") and cfg["entra"].get("client_id"):
        e = cfg["entra"]
        return Effective(provider="entra", source="database", issuer=e.get("issuer") or entra_issuer(e["tenant_id"], settings.graph_login_url),
                         client_id=e["client_id"], client_secret=settings.oidc_client_secret, tenant_id=e["tenant_id"],
                         default_role=role, auto_provision=auto)
    if provider == "google" and cfg["google"].get("client_id") and cfg["google"].get("allowed_domains"):
        g = cfg["google"]
        return Effective(provider="google", source="database", issuer=settings.google_issuer or GOOGLE_ISSUER, client_id=g["client_id"],
                         client_secret=settings.google_client_secret, allowed_domains=[d.lower() for d in g.get("allowed_domains", [])],
                         default_role=role, auto_provision=auto)
    if provider == "ldap" and cfg["ldap"].get("server_url") and cfg["ldap"].get("base_dn"):
        return Effective(provider="ldap", source="database", ldap={**DEFAULT_LDAP, **cfg["ldap"]}, ldap_password=settings.ldap_bind_password,
                         default_role=role, auto_provision=auto)
    if provider == "none" or provider in ("entra", "google", "ldap"):
        return base   # switched off, or chosen but not complete: nothing external is offered
    if settings.oidc_issuer and settings.oidc_client_id:   # legacy environment, unchanged behaviour
        return Effective(provider=settings.oidc_provider or "generic", source="environment", issuer=settings.oidc_issuer, client_id=settings.oidc_client_id,
                         client_secret=settings.oidc_client_secret, default_role=role, auto_provision=auto)
    return base


def validate(value: dict[str, Any], *, allow_http: bool = False) -> dict[str, Any]:
    """Validated copy of an administrator's input (non-secret fields only). Raises ValueError with a readable message."""
    provider = str(value.get("provider", "") or "")
    if provider not in PROVIDERS:
        raise ValueError(f"provider must be one of {PROVIDERS}")
    out = {**DEFAULT_STORED, "provider": provider}
    entra = value.get("entra") if isinstance(value.get("entra"), dict) else {}
    tenant = str(entra.get("tenant_id", "")).strip()
    if tenant and (tenant.lower() in FORBIDDEN_TENANTS or not TENANT.fullmatch(tenant)):
        raise ValueError("Entra tenant: give the tenant GUID or its domain; common, organizations and consumers are refused (they accept other tenants)")
    issuer = str(entra.get("issuer", "")).strip()
    if issuer:
        parsed_issuer = urlsplit(issuer)
        if (parsed_issuer.scheme != "https" and not (allow_http and parsed_issuer.scheme == "http")
                or not parsed_issuer.hostname or parsed_issuer.username or parsed_issuer.password
                or parsed_issuer.query or parsed_issuer.fragment
                or any(t in parsed_issuer.path.lower().split("/") for t in FORBIDDEN_TENANTS)):
            raise ValueError("Entra issuer must be an https URL for the configured tenant (never /common, /organizations or /consumers)")
        path_parts = [part for part in parsed_issuer.path.split("/") if part]
        # When the standard Entra authority is used, prevent a valid token from a
        # different tenant being accepted due to an issuer/tenant typo.
        if tenant and parsed_issuer.hostname.lower() == "login.microsoftonline.com" and path_parts:
            if path_parts[0].lower() != tenant.lower():
                raise ValueError("The Entra issuer tenant must match the configured Tenant ID")
    out["entra"] = {"tenant_id": tenant, "client_id": str(entra.get("client_id", "")).strip()[:200], "issuer": issuer[:300]}
    google = value.get("google") if isinstance(value.get("google"), dict) else {}
    domains = [str(d).strip().lower() for d in google.get("allowed_domains", []) if str(d).strip()]
    if any(not DOMAIN.fullmatch(d) for d in domains) or len(domains) > 20:
        raise ValueError("Google Workspace domains must be valid domain names (at most 20)")
    out["google"] = {"client_id": str(google.get("client_id", "")).strip()[:200], "allowed_domains": list(dict.fromkeys(domains))}
    ldap = value.get("ldap") if isinstance(value.get("ldap"), dict) else {}
    if "starttls" in ldap and not isinstance(ldap["starttls"], bool):
        raise ValueError("LDAP StartTLS must be a boolean")
    clean = {k: (bool(ldap.get(k, False)) if k == "starttls" else str(ldap.get(k, DEFAULT_LDAP[k]) or "").strip()) for k in DEFAULT_LDAP}
    clean["ca_pem"] = str(ldap.get("ca_pem", "") or "").strip()[:20000]
    if clean["server_url"]:
        ldap_url = urlsplit(clean["server_url"])
        if ldap_url.scheme.lower() not in ("ldaps", "ldap") or not ldap_url.hostname or ldap_url.username or ldap_url.password or ldap_url.query or ldap_url.fragment or ldap_url.path not in ("", "/"):
            raise ValueError("LDAP URL must start with ldaps:// or ldap://")
        try:
            if ldap_url.port is not None and not 1 <= ldap_url.port <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError("LDAP URL has an invalid port") from None
        if clean["server_url"].lower().startswith("ldap://") and not clean["starttls"]:
            raise ValueError("Use ldaps:// or enable StartTLS: a sign-in over plain LDAP would send passwords in clear")
    flt = clean["user_filter"] or "(objectClass=person)"
    if not (flt.startswith("(") and flt.endswith(")")) or flt.count("(") != flt.count(")") or "\x00" in flt:
        raise ValueError("The LDAP user filter must be a balanced, parenthesised filter")
    clean["user_filter"] = flt
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", clean["login_attribute"] or "uid"):
        raise ValueError("The login attribute must be a valid LDAP attribute name")
    clean["login_attribute"] = clean["login_attribute"] or "uid"
    out["ldap"] = clean
    role = value.get("default_role")
    if role not in (None, *ROLES):
        raise ValueError(f"default_role must be one of {ROLES}")
    out["default_role"] = role
    auto = value.get("auto_provision")
    if auto is not None and not isinstance(auto, bool):
        raise ValueError("auto_provision must be true or false")
    out["auto_provision"] = auto
    return out
