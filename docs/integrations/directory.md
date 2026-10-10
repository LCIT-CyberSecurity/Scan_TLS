# Directory connectors

A directory connector is **not** the sign-in mechanism. SSO (OIDC/Entra) and local accounts authenticate people; a
connector is a read-only lookup used by an administrator to **pre-provision** people with a role
(*Administration → Directory*). When a pre-provisioned person first signs in through SSO, their account is adopted by
e-mail address and keeps the chosen role (no duplicate, no default-role surprise).

| Connector | Settings | Secret | Tested against |
|---|---|---|---|
| LDAP / Active Directory | server URL (`ldap://`, `ldaps://`), bind DN (read-only), base DN, user filter, attributes, `tls_verify`, optional `ca_pem` | `TLS_SCAN_LDAP_BIND_PASSWORD[_FILE]` | a real OpenLDAP container (plain, LDAPS with untrusted and ignored certificates) |
| Microsoft Entra ID (Graph) | tenant id, client id | `TLS_SCAN_DIRECTORY_CLIENT_SECRET[_FILE]`; application permission `User.Read.All` (admin consent) | a Graph **mock** only |

*Test connection* reports per step with an explanation: DNS, connection/bind (wrong DN or password, untrusted TLS
certificate → install the CA / set `ca_pem`, timeout/firewall), search (wrong base DN, missing read permission), and for
Graph the token (`invalid_client`…) and `User.Read.All` (403). Search input is escaped (LDAP-filter injection tested).

Not implemented: **Google Workspace** (no way to test it here, so it is not offered), group/team synchronisation
(SI and tags are free classification here, not directory-driven).
