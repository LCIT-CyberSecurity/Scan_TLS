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
