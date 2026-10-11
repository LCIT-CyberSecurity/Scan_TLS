# External REST API (v1, read-only)

A JSON API to consult TLS scan results from your own tools (dashboards, scripts, reporting), authenticated by a **Personal API Token**.
It is a separate surface from the internal `/api/*` routes used by the WebUI, and from the session-based [results API](../user/api-results.md)
documented at `/swagger`.

* **Base path**: `/api/v1`. **Documentation**: Swagger UI at `/api/v1/docs`, OpenAPI document at `/api/v1/openapi.json`. Both describe only the routes below and answer `404` while the service is disabled.
* **Off by default.** It works only when an administrator enabled **External API** (*Administration → Settings*) **and** authorised your account (*Administration → Users → API*). The two conditions are independent of the role and also apply to administrators.
* **Read-only**: only `GET`. There is no way to launch, cancel or delete a scan, manage targets, policies, schedules, users or settings, or download report files.
* **HTTPS** is required for any remote use (the bundled reverse proxy already terminates TLS).

## Authentication

```
Authorization: Bearer tls_scan_pat_<secret>
```

* The owner generates the key in *Preferences → API and MCP access* (shown **once**). One active key per user; regenerating revokes the previous one; valid **90 days**; revocable at any time.
* Only the SHA-256 of the key is stored. A REST key never authenticates MCP and an MCP key never authenticates REST; neither opens a WebUI route, and a WebUI session is not accepted here.
* Every request re-checks, in the database: the global switch, the key, its expiry and revocation, that the user is active, the individual authorisation, and the user's **current role**. A role change, a withdrawn authorisation or a switched-off service applies immediately; no restart.
* All authentication failures answer the same `401 {"detail": "Authentication required"}` (the reason is only in the audit log).
* Rate limit: 120 requests per minute per key (`429` with `Retry-After`).

## Endpoints

| Route | Description |
|---|---|
| `GET /api/v1/me` | The account behind the key, its current role and the key prefix |
| `GET /api/v1/scans` | Scans, most recent first. Filters: `status`, `definition_id`, `si`, `tag`, `mine`, `started_after`, `started_before`; `limit` 1-100 (default 25), `offset` |
| `GET /api/v1/scans/{scan_id}` | Scan detail: engine summary, profile and policy versions, execution error, errors per endpoint, checks not performed |
| `GET /api/v1/scans/{scan_id}/summary` | Compact engine statistics (endpoints, compliance, findings by severity) |
| `GET /api/v1/scans/{scan_id}/endpoints` | TLS endpoints: versions, cipher suites, grade, compliance, certificate. Filters `compliance_status`, `severity`, `q`; paginated |
| `GET /api/v1/scans/{scan_id}/findings` | Findings with evidence, remediation and affected endpoints. Filters `severity`, `category`, `status`, `endpoint_id`; paginated |
| `GET /api/v1/scans/{scan_id}/comparison?with_scan=` | New / fixed / persistent / not-retested findings and endpoint changes, against `with_scan` or the previous comparable scan. **USER role or higher**, as in the WebUI (an AUDITOR key gets `403`) |

Output schemas are explicit: no internal object, scan configuration snapshot, worker data, file path, report download link or secret is returned.
Dates are ISO 8601; a value that was not collected is `null`. An unknown scan id answers `404`; an invalid one `422`.

## Authorisation model and its limit

TLS Scan has **global roles** (AUDITOR < USER < OPERATOR < ADMIN) and no per-SI access control; SI and tags only classify. The external API therefore applies exactly the
rules of the WebUI for the account's role (every role from AUDITOR reads all scans; comparison needs USER), and nothing broader. It does not invent a per-scope model.

## Examples

```bash
export TLS_SCAN=https://tls-scan.example.org:8443
export KEY='tls_scan_pat_…'          # from Preferences → API and MCP access

curl -sH "Authorization: Bearer $KEY" "$TLS_SCAN/api/v1/me"
curl -sH "Authorization: Bearer $KEY" "$TLS_SCAN/api/v1/scans?status=completed&limit=5"
curl -sH "Authorization: Bearer $KEY" "$TLS_SCAN/api/v1/scans/<scan_id>/findings?severity=high&limit=50"
curl -sH "Authorization: Bearer $KEY" "$TLS_SCAN/api/v1/scans/<scan_id>/comparison"
```

Use `-k` only for a self-signed certificate on a test installation.

## Errors

| Code | Meaning |
|---|---|
| 401 | Missing, invalid, expired or revoked key; service disabled; account not authorised or inactive; password change pending |
| 403 | The role of the account is insufficient for this route (comparison) |
| 404 | Unknown scan (or documentation requested while the service is off) |
| 405 | Any method other than `GET` |
| 422 | Invalid parameter (`limit` out of range, malformed id, unknown enum value) |
| 429 | Rate limit reached |

See also: [MCP server](mcp.md) · [administration](../admin/operations.md#external-api-and-mcp-access) · [user guide](../user/guide.md#api-and-mcp-access).
