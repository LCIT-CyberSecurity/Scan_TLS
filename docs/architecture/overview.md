# Architecture

```
 browser ──HTTPS──► webui (nginx: static React app, TLS, security headers)
                       │ /api
                       ▼
                     api (FastAPI) ──► PostgreSQL ◄── scheduler (due schedules → queued runs)
                                          ▲
                                          │ claim (FOR UPDATE SKIP LOCKED, advisory lock = global cap)
                                        worker ──spawn──► scan subprocess ──► tls_scanner engine ──► nmap / openssl
                                          │                       (no DB, stripped env)
                                          └──► reports + raw results on the `data` volume (/var/lib/tls-scan)
```

## Components

| Component | Code | Role |
|---|---|---|
| Engine | `tls_scanner/` | Unchanged business logic. `tls_scanner/runner.py` is the only addition: a headless entry point (`execute_scan`) with strict input validation, cooperative cancellation and per-host hooks. The CLI (`cli.run_job`) now shares `collect_job_results` with it, so both modes run identical scan code. |
| API | `backend/src/tls_scan_app/api/` | FastAPI. Every endpoint enforces its role server-side (`deps.require_role`). Cookie sessions + per-session CSRF token. |
| Worker | `workers/worker.py`, `workers/child.py` | Polls the queue, runs each scan in a **separate OS process group**, heartbeats, honours cancellation and the maximum duration (SIGTERM → partial results, then SIGKILL of the whole group, including nmap), persists results, queues notifications, delivers SMTP, applies retention. |
| Scheduler | `scheduler/scheduler.py` | Turns due schedules into queued runs, exactly once per occurrence. |
| External access | `api/external.py`, `mcp_server.py`, `services/external_access.py`, `api/access.py` | Read-only REST API v1 (`/api/v1`) and MCP server (`/mcp`), both off by default, authenticated by hashed access keys instead of sessions; they reuse the results API's handlers and output schemas. Details below. |
| Frontend | `frontend/` | Vite + React + TypeScript + Tailwind + shadcn-style components + lucide-react. Design tokens are LCIT-Sign's. FR/EN/DE. |

## Boundaries

* The engine knows nothing about users, roles, SSO, FastAPI, PostgreSQL or the frontend. It receives a
  validated `ScanJob`.
* The **run snapshot** (`scan_runs.config_snapshot`) is the single contract between API, scheduler and
  worker: targets grouped by ports, profile content + version, exact policy contents + versions, formats.
  The scan subprocess needs nothing else; it has **no database access** and an allow-listed environment
  (no session secret, no DB URL, no OIDC secret).

## Key mechanisms

* **Run lifecycle** — `queued → running → completed | partial | failed | cancelled | expired`
  (`scheduled` is the schedule itself). *partial* = some hosts were skipped (cancellation) or some endpoints
  had errors. A target with no TLS service is **not** an error and **never** a compliance result.
* **De-duplication** — `fingerprint` = hash of effective targets/ports, profile scan+checks, policy names +
  exact version ids and policy mode (not output formats nor worker count). A partial unique index on
  `scan_runs(fingerprint) WHERE status IN ('queued','running')` makes the database arbitrate concurrent
  requests: the loser attaches to the winner's run as an extra *requester* (`scan_run_requesters`) and gets
  read access only. Tested with 8 concurrent requests (`test_scans.py`).
* **Scheduling** — `UNIQUE(schedule_id, due_at)` on `schedule_triggers` + `FOR UPDATE SKIP LOCKED`:
  exactly once. An active run of the same schedule → `skipped_overlap`; an occurrence missed by more than
  15 minutes (downtime) → `skipped_late` (never replayed in a burst); wall-clock times follow the schedule's
  time zone (DST tested). Every decision is stored in `schedule_triggers` and shown in the UI.
* **Crash recovery** — a `running` run whose heartbeat is older than 120 s is failed explicitly
  (`worker lost`), never left running.
* **Versioning** — policies and profiles have immutable published versions; editing creates a draft;
  scans reference exact version ids; scheduled scans resolve the latest *published* version at fire time.
* **Storage** — structure in PostgreSQL (runs, endpoints, findings, certificate metadata, statistics);
  files on the `data` volume (`reports/<name>/{csv,markdown,html,cbom,metadata}`), each with a stored
  SHA-256 verified on download.
* **No per-SI access control** — SI, sub-SI and tags only classify and filter (polymorphic
  `resource_tags` / `resource_si`). Roles are global.

## External API and MCP

Two independent, read-only services share the API process (no extra container) and PostgreSQL. They are **not** the internal `/api/*` routes: the WebUI keeps its cookie session + CSRF, and external keys open nothing internal.

```
 client ──HTTPS──► nginx ──/api/v1/*──► FastAPI router `external`  (Bearer tls_scan_pat_…)  ──► handlers of `api/results.py` ──► same services/models as the WebUI
                       └──/mcp──────► ASGI MCP app (official SDK, Streamable HTTP, mounted at the root) (Bearer tls_scan_mcp_…) ──► same handlers, closed tool list
```

* **Gates, in order, on every request / tool call** (`services/external_access.authenticate`): key family (prefix) → global switch (`system_settings.external_access`) → key hash → expiry → revocation → user active → individual flag (`users.api_access_enabled` / `mcp_access_enabled`) → no pending password change. The role is read from the user row each time; nothing is frozen in the key.
* **Keys**: `access_tokens` (service `api`/`mcp`, prefix, SHA-256, created / expires (+90 d) / last used / revoked). A partial unique index allows one non-revoked key per user and service. Regeneration revokes the old key; withdrawing the individual authorisation or deactivating the user revokes the keys; switching a service off *suspends* keys (checked at use) without revoking them.
* **Visibility** is the WebUI's: roles are global, there is no per-SI scope to invent. AUDITOR and above read every scan; comparison needs USER (`403` for an AUDITOR key).
* **Responses** go through explicit Pydantic models (`ExtScan`, `ExtScanDetail`, `Endpoint`, `Finding`, `Comparison`): the run snapshot, progress, worker data, file paths, report links and secrets are not part of them.
* **Documentation**: `/api/v1/docs` + `/api/v1/openapi.json` (generated from the `/api/v1` router only; `404` while disabled). The session-based `/swagger` (results API) is unchanged.
* **MCP transport**: DNS-rebinding protection (Host/Origin lists), 64 KB body limit, per-key limits, 25 s tool timeout; nginx forwards `/mcp` with buffering off. The MCP session manager runs in the FastAPI lifespan; `redirect_slashes` is off so `/mcp` answers exactly.
* **Audit**: `external_access.*` (switches, authorisations, key created/refused/revoked), `external_api.*` (denials, rate limits, scan reads), `mcp.*` (tool calls and denials). Secrets never appear (the audit scrubber also masks sensitive field names).
* Not available in Standalone: the CLI has no HTTP or MCP server.

## Security notes

* Nmap is never given a user-provided command string: targets/ports pass `services/targets.py` and
  `runner.validate_scan_input` (FQDN / IP / CIDR / port-list whitelist; leading `-`, spaces, shell
  metacharacters rejected) before python-nmap builds its arguments.
* No business restriction on scanned ranges (private networks are allowed), but limits apply: total
  addresses per scan, global concurrent scans, scan duration, workers per scan, container CPU/memory/pids.
* Containers: `cap_drop: ALL`, `no-new-privileges`, read-only root fs, database network `internal`, worker
  alone on the `scan` egress network.
* Cookies `HttpOnly; SameSite=Lax; Secure` (production refuses `cookie_secure=false` and development secrets).
* Reports are served with `Content-Security-Policy: sandbox`, `nosniff`.
