"""LDAP / Active Directory connector (read-only bind)."""
from __future__ import annotations

import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from ldap3 import NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError
from ldap3.utils.conv import escape_filter_chars

from tls_scan_app.connectors.base import ConnectorError, DirectoryPerson, Step


def _first(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    return "" if value is None else str(value)


class LdapConnector:
    kind = "ldap"

    def __init__(self, cfg: dict[str, Any], bind_password: str) -> None:
        self.cfg, self.password = cfg, bind_password
        self.mail = cfg.get("email_attribute") or "mail"
        self.name = cfg.get("name_attribute") or "cn"
        self.id_attr = cfg.get("id_attribute") or "entryUUID"
        self.user_filter = cfg.get("user_filter") or "(objectClass=person)"

    def _server(self) -> Server:
        url = urlparse(self.cfg["server_url"])
        use_ssl = url.scheme == "ldaps"
        tls = None
        if use_ssl or self.cfg.get("starttls"):
            tls = Tls(validate=ssl.CERT_REQUIRED if self.cfg.get("tls_verify", True) else ssl.CERT_NONE,
                      ca_certs_data=self.cfg.get("ca_pem") or None)
        return Server(url.hostname, port=url.port or (636 if use_ssl else 389), use_ssl=use_ssl, tls=tls, get_info=NONE, connect_timeout=8)

    def _connect(self) -> Connection:
        conn = Connection(self._server(), user=self.cfg.get("bind_dn") or None, password=self.password or None, receive_timeout=15, auto_bind=False)
        conn.open()
        if self.cfg.get("starttls"):
            conn.start_tls()
        if not conn.bind():
            raise ConnectorError(f"bind refused: {conn.result.get('description')}")
        return conn

    def diagnose(self) -> list[Step]:
        steps: list[Step] = []
        try:
            url = urlparse(self.cfg["server_url"])
            socket.getaddrinfo(url.hostname, url.port or 389)
            steps.append(Step("dns", "ok", url.hostname or ""))
        except (OSError, KeyError, ValueError) as error:
            steps.append(Step("dns", "fail", f"Cannot resolve the server: {error}"))
            return steps
        try:
            conn = self._connect()
            steps.append(Step("connect+bind", "ok"))
        except ConnectorError as error:
            steps.append(Step("connect+bind", "fail", f"{error}. Check the bind DN and password (TLS_SCAN_LDAP_BIND_PASSWORD)."))
            return steps
        except LDAPSocketOpenError as error:
            text = str(error)
            hint = ("TLS certificate not trusted: provide the CA in 'ca_pem' or fix the server certificate."
                    if "certificate" in text.lower() or "ssl" in text.lower() else "Connection refused or timed out: check host, port and firewall.")
            steps.append(Step("connect+bind", "fail", f"{hint} ({text[:160]})"))
            return steps
        except (LDAPBindError, LDAPException, OSError) as error:
            steps.append(Step("connect+bind", "fail", f"{type(error).__name__}: {str(error)[:200]}"))
            return steps
        try:
            conn.search(self.cfg["base_dn"], self.user_filter, SUBTREE, attributes=[self.mail], size_limit=1)
            if conn.result.get("description") not in ("success", "sizeLimitExceeded"):
                raise ConnectorError(conn.result.get("description", "search failed"))
            steps.append(Step("search", "ok", f"base {self.cfg['base_dn']}"))
        except (ConnectorError, LDAPException, KeyError) as error:
            steps.append(Step("search", "fail", f"Search failed: {error}. Check the base DN and the account's read permission."))
        finally:
            conn.unbind()
        return steps

    def search(self, query: str, limit: int = 25) -> list[DirectoryPerson]:
        q = escape_filter_chars(query.strip())
        flt = f"(&{self.user_filter}(|({self.mail}=*{q}*)({self.name}=*{q}*)))"
        try:
            conn = self._connect()
        except (ConnectorError, LDAPException, OSError) as error:
            raise ConnectorError(str(error)[:200]) from error
        try:
            conn.search(self.cfg["base_dn"], flt, SUBTREE, attributes=[self.mail, self.name, self.id_attr], size_limit=limit)
            return [DirectoryPerson(_first(e.entry_attributes_as_dict.get(self.id_attr)) or e.entry_dn, _first(e.entry_attributes_as_dict.get(self.mail)),
                                    _first(e.entry_attributes_as_dict.get(self.name))) for e in conn.entries if _first(e.entry_attributes_as_dict.get(self.mail))]
        finally:
            conn.unbind()
