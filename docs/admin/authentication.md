# Authentication (Administration → Authentication)

TLS Scan signs people in with **local accounts** (always available) and, optionally, **one external provider at a time**:

| Provider | Protocol | What proves who the person is |
|---|---|---|
| Microsoft Entra ID | OpenID Connect (Authorization Code + PKCE S256) | the signed ID token of **your tenant** |
| Google Workspace | OpenID Connect (Authorization Code + PKCE S256) | the signed ID token, with the signed `hd` claim of an **allowed Workspace domain** |
| LDAP / Active Directory / OpenLDAP | directory password (not a single sign-on) | a bind as the user, after a unique lookup of the account |

If an OIDC federation is already available in front of your directory, prefer it to LDAP.

Sessions, CSRF, roles and the audit log are TLS Scan's own: no provider adds a second session system, and **a provider never
decides a role** (no role is derived from groups or claims). The API and MCP keys are independent of the web sign-in.

## Where the settings live (priority rule)

1. **Administration → Authentication** (stored in the database) when it names a provider;
2. otherwise the **server environment** `TLS_SCAN_OIDC_*` (existing installations keep working untouched after an update);
3. choosing *Local accounts only* switches the external sign-in off even if the environment still describes one.

**Secrets never live in the database or in the API.** They come from the environment or a protected file (`*_FILE`):

| Secret | Variable |
|---|---|
| Entra / generic OIDC client secret | `TLS_SCAN_OIDC_CLIENT_SECRET` (`TLS_SCAN_OIDC_CLIENT_SECRET_FILE`) |
| Google OAuth client secret | `TLS_SCAN_GOOGLE_CLIENT_SECRET` (`…_FILE`) |
| LDAP service-account password | `TLS_SCAN_LDAP_BIND_PASSWORD` (`…_FILE`) |
| Google Admin SDK key (directory lookup only) | `TLS_SCAN_GOOGLE_DIRECTORY_KEY_FILE` |

The page only shows whether each secret is set.

## People, roles and accounts

- The stable identity is **(issuer, subject)**, never the e-mail. A person pre-provisioned in **Administration → Directory**
  (account `Pre-provisioned`, with the role you chose) is adopted at their first sign-in by e-mail — and only that kind of account:
  a local, SSO or LDAP account is never taken over through an e-mail match, and an unknown person whose e-mail is already used by
  another account is refused (`email_conflict`), not merged.
- **First sign-in of an unknown person**: *Refuse (pre-provisioning required)* or *Create the account with the default role*
  (AUDITOR, USER or OPERATOR — never ADMIN). Installations that already had SSO users keep *Create*; a new installation starts with
  *Refuse*, unless `TLS_SCAN_SSO_AUTO_PROVISION=true`.
- Roles stay those of TLS Scan (AUDITOR, USER, OPERATOR, ADMIN); an administrator changes them in Administration → Users, where the
  **Source** of each account (Local, Entra ID, Google Workspace, LDAP, Pre-provisioned) is shown. A role survives the next sign-in.
- A **disabled account is refused whatever the provider**, its open sessions stop working and its API / MCP keys are revoked.
  History and owned resources are kept.
- **Emergency access**: the local administrator keeps working when the provider is down. The last active administrator with a local
  password cannot be demoted or disabled. The initial password is never reset by an update.

## Microsoft Entra ID

1. Entra admin center → *App registrations* → *New registration*, **single tenant**.
2. *Authentication* → add a **Web** platform with the redirect URI shown on the page
   (`<TLS_SCAN_PUBLIC_BASE_URL>/api/auth/sso/callback`, https in production).
3. *Certificates & secrets* → new client secret → put it in `TLS_SCAN_OIDC_CLIENT_SECRET`.
4. *Token configuration* → add the optional `email` claim if the sign-in name is not an e-mail address.
5. In TLS Scan: provider *Microsoft Entra ID*, **Tenant ID** and **Client ID** (the issuer is built from the tenant).
   The multi-tenant endpoints `common`, `organizations`, `consumers` are refused, and the token's `tid` must be your tenant.

Microsoft Graph is **not** needed to sign in. It is only used by the optional directory lookup (Administration → Directory,
application permission `User.Read.All`, secret `TLS_SCAN_DIRECTORY_CLIENT_SECRET`).

## Google Workspace

1. Google Cloud console → project → *OAuth consent screen* (Internal for a Workspace-only audience).
2. *Credentials* → *OAuth client ID* of type **Web application**, authorised redirect URI = the one shown on the page.
3. Client secret in `TLS_SCAN_GOOGLE_CLIENT_SECRET`.
4. In TLS Scan: provider *Google Workspace*, **Client ID** and the **allowed Workspace domains**. Without a domain the provider is not
   offered. The signed `hd` claim must be one of them and the e-mail must be verified: the e-mail suffix alone is never trusted and
   personal Google accounts are refused.

Directory lookup (optional, separate from the sign-in): a service account with domain-wide delegation of the single scope
`admin.directory.user.readonly`, its JSON key file in `TLS_SCAN_GOOGLE_DIRECTORY_KEY_FILE`, and the Workspace domain plus the
delegated administrator's e-mail in Administration → Directory.

## LDAP / Active Directory / OpenLDAP

Directory name, URL (`ldaps://…`, or `ldap://…` with StartTLS), base DN, login attribute (`uid`, `sAMAccountName`…), user filter,
service account DN (+ `TLS_SCAN_LDAP_BIND_PASSWORD`), optional custom CA (PEM), e-mail / name / stable-id attributes
(`entryUUID` for OpenLDAP, `objectGUID` for Active Directory).

- **LDAPS or StartTLS is mandatory and the server certificate is always validated**; give the issuing CA for an internal PKI.
  Plain LDAP is refused when you save.
- The separate directory lookup also validates certificates in production; a saved `tls_verify: false` setting is ignored there.
- The person is looked up with the service account (filter escaped, 2 results at most): zero or several matches never authenticate.
  The password is then verified by a bind as the user. An empty password is refused (it would be an anonymous bind).
- Every failure answers the same `Invalid credentials` to the browser (no account probing); the reason is in the audit log and in
  the diagnostics below. Failed attempts are throttled like the local sign-in. No password is ever logged or stored.
- The directory entry needs an e-mail attribute.

## Test the configuration, diagnostics

**Test the configuration** runs step-by-step checks:

- Entra / Google: parameters, client secret, tenant / domain restriction, redirect URI, issuer reachable, OpenID document coherence,
  signing keys (JWKS). The last step says plainly that these checks **do not prove** that a person can sign in: use the button with a
  test account, and with an account outside the tenant / domain, which must be refused.
- LDAP: configuration, transport security, DNS, TCP, TLS certificate, service-account bind, base DN, user search, and — only when you
  type a test login and password and click — a real user authentication (the password is used once and never kept).

**Latest sign-in diagnostics** lists the recent failures with an explanation: `AADSTS50011` (redirect URI), `invalid_client`,
`invalid_grant`, tenant / issuer, nonce / state, JWKS, `redirect_uri_mismatch`, account outside the Workspace domain, and for LDAP
server unreachable, timeout, untrusted certificate, service bind refused, wrong base DN, invalid filter, ambiguous account.
Secrets, codes and tokens are never logged.

## Tests

The automated tests use the **mock** OIDC provider and the OpenLDAP lab container (with a private CA): they validate TLS Scan's
rules (tenant, `hd`, state, nonce, audience, expiry, replay, account policy, LDAP security), **not a real Entra tenant or Google
Workspace**. A real-tenant check is a manual step: configure the provider, run *Test the configuration*, then sign in with a test
account and with an account that must be refused.
