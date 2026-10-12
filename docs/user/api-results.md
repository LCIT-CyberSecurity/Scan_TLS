# Results API (V1, read-only)

A JSON API to consult scan results, documented in **Swagger UI** at `https://<server>:<port>/swagger` (the trailing-slash form works too).

- **Authentication**: the TLS Scan session. Sign in to the WebUI in the same browser, then open `/swagger`; *Try it out* sends your session cookie. This API is for in-browser use; for scripts and tools with a personal API key see the [external API](../integrations/external-api.md) (`/api/v1`). Without a session, `/swagger`, its OpenAPI document (`/swagger/openapi.json`) and every `/api/results` route answer `401`.
- **Roles**: AUDITOR, USER, OPERATOR and ADMIN can list and read scans, endpoints, findings and reports. Comparison needs USER or higher (as in the WebUI). Rights are those of the internal API; nothing is widened.
- **Read-only**: only `GET`. The Swagger document describes `/api/results` only; launch, cancel, delete and administration operations stay internal to the WebUI and are not documented.
- **Swagger UI is served locally** (no CDN) under a strict Content-Security-Policy.

| Endpoint | Purpose |
|---|---|
| `GET /api/results` | List scans (filters: `status`, `definition_id`, `si`, `tag`, `mine`, `requested_by`, `started_after/before`, `finished_after/before`; `limit` 1-200, `offset`) |
| `GET /api/results/{run_id}` | Scan detail: summary, profile, policy versions, errors, checks not performed, reports |
| `GET /api/results/{run_id}/endpoints` | TLS endpoints: versions, cipher suites, grade, compliance, certificate (filters: `compliance_status`, `severity`, `q`) |
| `GET /api/results/{run_id}/findings` | Findings with evidence and remediation (filters: `severity`, `category`, `status`, `endpoint_id`) |
| `GET /api/results/{run_id}/compare?with_run=` | New / fixed / persistent / not retested findings, endpoint changes |
| `GET /api/results/{run_id}/reports` | Available reports with their recorded SHA-256 |
| `GET /api/results/{run_id}/reports/{format}` | Download (`html`, `md`, `csv`, `findings_csv`, `cbom`, `metadata`); SHA-256 verified, HTML sandboxed |

Data semantics: values are those collected by the engine. Anything not collected is `null` (for instance the certificate start of validity, which the engine does not store, or `summary` on a scan that has no results). A finding on an endpoint that was not tested again is `not_retested`, never `fixed`.

Notes: the internal `/api/docs` and `/api/openapi.json` are no longer published; `/swagger` is the only API documentation. Behind Nginx, `/swagger` is proxied to the API (see `ops/docker/nginx/default.conf`).

Endpoints also expose `tls_checks` (complementary TLS checks, empty when the profile did not enable any), separate from the grade and
the findings: see [Complementary TLS checks](tls-checks.md).
