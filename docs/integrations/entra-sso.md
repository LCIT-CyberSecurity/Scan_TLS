# SSO with Microsoft Entra ID (and generic OIDC)

TLS Scan implements OpenID Connect *Authorization Code + PKCE* with ID-token validation (issuer, audience,
nonce, signature via JWKS). **Authentication and directory are separate**: SSO only identifies people; no
directory connector (LDAP/AD/Google/Graph directory sync) is implemented in V1 — users are provisioned at first
sign-in and managed in *Administration → Users*.

## Entra ID
1. *App registrations → New registration*, single tenant, redirect URI (Web):
   `https://<host>/api/auth/sso/callback` (must equal `TLS_SCAN_PUBLIC_BASE_URL` + that path).
2. *Certificates & secrets*: create a client secret. *Token configuration*: add the optional claim `email`
   (otherwise the `preferred_username`/`upn` is used when it is an address).
3. `.env`:
   ```
   TLS_SCAN_OIDC_PROVIDER=entra
   TLS_SCAN_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
   TLS_SCAN_OIDC_CLIENT_ID=<application (client) id>
   TLS_SCAN_OIDC_CLIENT_SECRET=<secret>
   TLS_SCAN_OIDC_DEFAULT_ROLE=USER
   ```
   then `docker compose up -d api`. A "Sign in with SSO" button appears; the local administrator keeps working.
4. Promote people in *Administration → Users*.

## Troubleshooting
Failures are audited (`auth.sso_login`, `reason` = `oidc_exchange_failed` | `provider_unreachable` |
`account_disabled`) with a scrubbed detail, e.g. `invalid_client` (wrong secret), `AADSTS50011` (redirect URI
mismatch), "ID token carries no e-mail address" (add the `email` claim). The browser only ever sees a generic
"Sign-in failed".

## Status of testing
Covered automatically against a mock OIDC provider (`tests/lab/mock_oidc`, CrashTest): provisioning, default role,
role persistence across logins, tampered state, disabled account. **A real Entra ID tenant has not been tested yet**
(planned: see [limitations](../limitations.md)).
