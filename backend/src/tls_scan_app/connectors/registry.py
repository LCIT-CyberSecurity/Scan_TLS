from __future__ import annotations

from sqlalchemy.orm import Session as DbSession

from tls_scan_app.config import Settings
from tls_scan_app.connectors.base import DirectoryConnector
from tls_scan_app.connectors.entra import EntraConnector
from tls_scan_app.connectors.google import GoogleConnector
from tls_scan_app.connectors.ldap import LdapConnector
from tls_scan_app.models import SystemSetting

KINDS = ("none", "ldap", "entra", "google")


def directory_config(db: DbSession) -> dict:
    row = db.get(SystemSetting, "directory")
    return row.value if row else {"kind": "none"}


def build_connector(db: DbSession, settings: Settings) -> DirectoryConnector | None:
    cfg = directory_config(db)
    if cfg.get("kind") == "ldap" and cfg.get("ldap", {}).get("server_url") and cfg["ldap"].get("base_dn"):
        ldap_cfg = dict(cfg["ldap"])
        if settings.environment == "production":
            ldap_cfg["tls_verify"] = True
        return LdapConnector(ldap_cfg, settings.ldap_bind_password)
    entra = cfg.get("entra", {})
    if cfg.get("kind") == "entra" and entra.get("tenant_id") and entra.get("client_id"):
        return EntraConnector(entra, settings.directory_client_secret, settings.graph_login_url, settings.graph_base_url)
    google = cfg.get("google", {})
    if cfg.get("kind") == "google" and google.get("domain") and google.get("admin_email"):
        return GoogleConnector(google, settings.google_directory_key_file)
    return None
