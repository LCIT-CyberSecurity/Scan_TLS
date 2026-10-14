"""Turn what a provider answered into something an administrator can act on. Pure text handling, no secret ever goes through here."""
from __future__ import annotations

import re

# (code, regex over the scrubbed provider error, explanation shown to the administrator)
RULES: list[tuple[str, str, str]] = [
    ("aadsts50011", r"AADSTS50011|redirect_uri.*(not match|mismatch)", "The redirect URI sent by TLS Scan is not registered on the application. Add exactly {redirect} as a Web redirect URI."),
    ("redirect_uri_mismatch", r"redirect_uri_mismatch", "Google refuses the redirect URI. Add exactly {redirect} to the authorised redirect URIs of the OAuth client."),
    ("invalid_client", r"invalid_client|AADSTS7000215|AADSTS7000222|AADSTS70002", "The client ID or client secret is wrong, or the secret has expired. Check the application and renew the secret."),
    ("invalid_grant", r"invalid_grant|AADSTS54005|AADSTS70008|AADSTS50013", "The provider refused the authorisation code (already used, expired, or a redirect URI / PKCE mismatch). Try the sign-in again."),
    ("tenant_mismatch", r"tenant|AADSTS50020|AADSTS700016|AADSTS90002|issuer", "The account or the token does not belong to the configured tenant / issuer. Check the tenant ID and the issuer."),
    ("workspace_domain", r"workspace|hosted domain|\bhd\b", "The Google account is not in an allowed Workspace domain."),
    ("nonce", r"nonce", "The token does not match the sign-in attempt (nonce). Start again from the login page."),
    ("state", r"login state|state", "The sign-in state is missing or altered (cookie expired, or the sign-in was not started from this application)."),
    ("jwks", r"jwks", "The provider's signing keys could not be fetched. Check that the server can reach the provider (proxy, firewall, DNS)."),
    ("token_invalid", r"Invalid ID token|expired|signature|audience|aud", "The ID token was refused (signature, audience, issuer or dates). Check the client ID and that the clocks are in sync."),
    ("discovery", r"discovery|unreachable|connect|timed out|timeout", "The provider's OpenID configuration cannot be reached. Check the issuer URL and the server's network access."),
    ("no_email", r"no e-mail|e-mail address", "The token carries no usable e-mail address. Add the email claim (Entra: optional claim) so the account can be matched."),
    ("not_provisioned", r"not_provisioned", "This person has no TLS Scan account and automatic creation is off. Pre-provision them in Administration → Directory."),
    ("email_conflict", r"email_conflict", "Another account already uses this e-mail address under a different identity. It is never merged automatically."),
    ("account_disabled", r"account_disabled", "The account is disabled in TLS Scan."),
    # LDAP
    ("ldap_unreachable", r"ldap_unreachable|name or service not known|connection refused|socket", "The directory server cannot be reached. Check host, port and firewall."),
    ("ldap_timeout", r"ldap_timeout", "The directory did not answer in time."),
    ("ldap_tls", r"ldap_tls|certificate|ssl", "The directory's TLS certificate is not trusted. Provide the issuing CA in the configuration or fix the server certificate."),
    ("ldap_service_bind", r"ldap_service_bind|invalid credentials.*service", "The service account was refused. Check the bind DN and the password variable."),
    ("ldap_base_dn", r"ldap_base_dn|no such object", "The base DN does not exist on this directory."),
    ("ldap_filter", r"ldap_filter|filter", "The LDAP filter or login attribute is invalid."),
    ("ldap_ambiguous", r"ldap_ambiguous", "Several directory entries match this login: it is refused until the directory is made unambiguous."),
    ("ldap_bad_credentials", r"ldap_bad_credentials", "Wrong login or password."),
]


def explain(text: str, *, redirect: str = "") -> dict[str, str]:
    """{code, explanation} for the first rule that matches; `unknown` otherwise."""
    low = (text or "").lower()
    for code, _, explanation in RULES:   # a diagnostics code named by our own code wins over the free-text patterns
        if re.search(rf"(^|[^a-z0-9_]){re.escape(code)}([^a-z0-9_]|$)", low):
            return {"code": code, "explanation": explanation.replace("{redirect}", redirect or "the redirect URI shown in the page")}
    for code, pattern, explanation in RULES:
        if re.search(pattern, text or "", re.IGNORECASE):
            return {"code": code, "explanation": explanation.replace("{redirect}", redirect or "the redirect URI shown in the page")}
    return {"code": "unknown", "explanation": "The sign-in failed for a reason that is not recognised; see the server logs."}
