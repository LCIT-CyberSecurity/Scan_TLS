"""Sign in with a directory password (LDAP / Active Directory / OpenLDAP) through ldap3.

Not a single sign-on protocol: TLS Scan looks the account up with a read-only service account, then verifies the password by
binding AS that account. Passwords are never logged, never stored and never put on a command line. Plain LDAP is refused.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from ldap3 import NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPInvalidFilterError, LDAPSocketOpenError, LDAPSocketReceiveError
from ldap3.utils.conv import escape_filter_chars

MAX_LOGIN = 256
CONNECT_TIMEOUT = 8
RECEIVE_TIMEOUT = 15


class LdapAuthError(Exception):
    """`code` is one of the ldap_* diagnostics codes; the message never contains a password."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(code)
        self.code, self.message = code, message


@dataclass(frozen=True)
class LdapIdentity:
    dn: str
    subject: str
    email: str
    name: str
    login: str


def _first(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return "" if value is None else str(value)


def require_secure(cfg: dict[str, Any]) -> None:
    parsed = urlparse(str(cfg.get("server_url", "")))
    if (parsed.scheme.lower() not in ("ldaps", "ldap") or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise LdapAuthError("ldap_tls", "Use a valid LDAP URL without embedded credentials or a base-DN path")
    try:
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
    except ValueError:
        raise LdapAuthError("ldap_tls", "The LDAP URL contains an invalid port") from None
    if not (parsed.scheme.lower() == "ldaps" or (parsed.scheme.lower() == "ldap" and cfg.get("starttls"))):
        raise LdapAuthError("ldap_tls", "Use ldaps:// or enable StartTLS: passwords are never sent over plain LDAP")


def build_server(cfg: dict[str, Any]) -> Server:
    """Server object with certificate validation ALWAYS on (a custom CA can be given, validation is never switched off here)."""
    url = urlparse(str(cfg["server_url"]))
    use_ssl = url.scheme == "ldaps"
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=cfg.get("ca_pem") or None)
    return Server(url.hostname, port=url.port or (636 if use_ssl else 389), use_ssl=use_ssl, tls=tls, get_info=NONE, connect_timeout=CONNECT_TIMEOUT)


def _open(cfg: dict[str, Any], user: str | None, password: str | None) -> Connection:
    conn = Connection(build_server(cfg), user=user, password=password, receive_timeout=RECEIVE_TIMEOUT, auto_bind=False)
    try:
        conn.open()
        if cfg.get("starttls") and not str(cfg["server_url"]).lower().startswith("ldaps://") and not conn.start_tls():
            raise LdapAuthError("ldap_tls", "StartTLS was refused by the server")
    except LDAPSocketOpenError as error:
        text = str(error).lower()
        if "certificate" in text or "ssl" in text or "tls" in text:
            raise LdapAuthError("ldap_tls", "The server certificate is not trusted") from error
        raise LdapAuthError("ldap_unreachable", "The directory cannot be reached") from error
    except (socket.timeout, TimeoutError, LDAPSocketReceiveError) as error:
        raise LdapAuthError("ldap_timeout", "The directory did not answer in time") from error
    except LDAPException as error:
        text = str(error).lower()
        raise LdapAuthError("ldap_tls" if ("certificate" in text or "ssl" in text) else "ldap_unreachable", type(error).__name__) from error
    except OSError as error:
        raise LdapAuthError("ldap_unreachable", type(error).__name__) from error
    return conn


def login_filter(cfg: dict[str, Any], login: str) -> str:
    flt = cfg.get("user_filter") or "(objectClass=person)"
    return f"(&{flt}({cfg.get('login_attribute') or 'uid'}={escape_filter_chars(login)}))"


def find_entry(cfg: dict[str, Any], service_password: str, login: str) -> tuple[str, dict[str, Any]]:
    """The one directory entry for this login. Several matches are refused: nobody can tell which person is signing in."""
    require_secure(cfg)
    bind_dn = cfg.get("bind_dn") or None
    if bind_dn and not service_password:
        raise LdapAuthError("ldap_service_bind", "A service bind DN is configured but its password is missing")
    conn = _open(cfg, bind_dn, service_password or None)
    try:
        try:
            bound = conn.bind()
        except LDAPBindError as error:
            raise LdapAuthError("ldap_service_bind", "The service account was refused") from error
        except (LDAPSocketReceiveError, socket.timeout) as error:
            raise LdapAuthError("ldap_timeout", "The directory did not answer in time") from error
        if not bound:
            raise LdapAuthError("ldap_service_bind", "The service account was refused")
        attrs = sorted({a for a in (cfg.get("email_attribute") or "mail", cfg.get("name_attribute") or "cn", cfg.get("id_attribute") or "entryUUID",
                                     cfg.get("login_attribute") or "uid") if a})
        try:
            ok = conn.search(cfg["base_dn"], login_filter(cfg, login), SUBTREE, attributes=attrs, size_limit=2, time_limit=RECEIVE_TIMEOUT)
        except LDAPInvalidFilterError as error:
            raise LdapAuthError("ldap_filter", "The LDAP filter or login attribute is invalid") from error
        except LDAPException as error:
            raise LdapAuthError("ldap_filter" if "filter" in str(error).lower() else "ldap_base_dn", type(error).__name__) from error
        description = (conn.result or {}).get("description")
        if description == "noSuchObject":
            raise LdapAuthError("ldap_base_dn", "The base DN does not exist")
        if description not in ("success", "sizeLimitExceeded"):
            raise LdapAuthError("ldap_filter", str(description))
        entries = [e for e in conn.response or [] if e.get("type") == "searchResEntry"] if ok or description == "sizeLimitExceeded" else []
        if not entries:
            raise LdapAuthError("ldap_bad_credentials", "no such account")
        if len(entries) > 1:
            raise LdapAuthError("ldap_ambiguous", "several accounts match")
        return str(entries[0]["dn"]), dict(entries[0].get("attributes") or {})
    finally:
        conn.unbind()


def authenticate(cfg: dict[str, Any], service_password: str, login: str, password: str) -> LdapIdentity:
    """Verify the password by binding as the user. Raises LdapAuthError; returns the directory identity on success."""
    login = (login or "").strip()
    if not login or len(login) > MAX_LOGIN or "\x00" in login or not password or "\x00" in password:
        raise LdapAuthError("ldap_bad_credentials", "empty or invalid login")   # an empty password would be an anonymous bind: never
    dn, attrs = find_entry(cfg, service_password, login)
    conn = _open(cfg, dn, password)
    try:
        try:
            if not conn.bind():
                raise LdapAuthError("ldap_bad_credentials", "wrong password")
        except LDAPBindError as error:
            raise LdapAuthError("ldap_bad_credentials", "wrong password") from error
        except (LDAPSocketReceiveError, socket.timeout) as error:
            raise LdapAuthError("ldap_timeout", "The directory did not answer in time") from error
    finally:
        conn.unbind()
    ident_attr = cfg.get("id_attribute") or "entryUUID"
    return LdapIdentity(dn=dn, subject=_first(attrs.get(ident_attr)) or dn, email=_first(attrs.get(cfg.get("email_attribute") or "mail")).lower(),
                        name=_first(attrs.get(cfg.get("name_attribute") or "cn")), login=login)


def issuer_for(cfg: dict[str, Any]) -> str:
    """Stable per-directory identity namespace: two directories never share accounts."""
    host = urlparse(str(cfg.get("server_url", ""))).hostname or "directory"
    return f"ldap:{(cfg.get('name') or host).strip().lower()}"[:500]
