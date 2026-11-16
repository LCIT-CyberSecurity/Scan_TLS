# Runtime and dependency inventory (TScan-0001)

Inventory checked on 16 November 2026 on Debian 13.7 (Trixie), both on the development host and on the Integrations VM. The Integrations VM already runs the `tls-scan` Compose project; its existing database volume was not modified.

## Observed versions and decisions

| Component | Before | Change / current target | Decision |
| --- | --- | --- | --- |
| Integrations host | Debian 13.7 | Debian 13.7 | Already Trixie; no host migration was needed. |
| API, worker, scheduler base | `python:3.12-slim-trixie`; deployed Python 3.12.15 | Unchanged | Already Debian 13. Keep Python 3.12 as the supported image runtime; Python 3.13.5 is available on the Debian 13 development host and used for the standalone compatibility check. |
| Frontend build image | `node:20-alpine` | `node:24-trixie-slim` | Move to a maintained Node LTS and Debian 13. Node 24 is the conservative LTS choice with broad ecosystem support. |
| Nginx runtime | `nginx:1.27-alpine`; deployed Nginx 1.27.5 | `nginx:1.30.6-trixie` | Use the stable Nginx series on Debian 13; the official image publishes a Trixie variant. |
| PostgreSQL | `postgres:16-alpine`; deployed PostgreSQL 16.15 | Unchanged | Keep major version 16 and the current Alpine image to avoid changing the base OS of an existing persistent database without a separate restore/migration rehearsal. No data migration was run. |
| OpenSSL / Nmap | API container: OpenSSL 3.5.7, Nmap 7.95 | Unchanged | Current Debian 13 packages; preserve TLS and PQC behavior. |
| Frontend packages | Existing npm lockfile; Tailwind 3 and React 19 | Refreshed lockfile within existing semver ranges | `npm update` refreshed compatible versions without changing the declared package ranges or upgrading Tailwind's major version. LST-7 owns the Tailwind 4 decision. |
| Standalone Python requirements | Unlocked `requirements.txt`; Python requirement `>=3.12` | No new Python lock introduced | The standalone dependency file has no lock format to update. Keep project dependency declarations as ranges; verify installation/runtime on Python 3.13 instead of generating a speculative lock. |
| CI frontend runtime | Node 20 | Node 24 | Keep CI aligned with the production frontend build runtime. |

The frontend lockfile resolves React/React DOM 19.3.1, React Router 7.18.5, Vite 6.4.6, TypeScript 5.9.3, Tailwind 3.4.19 and Vitest 2.1.9. Existing Python project ranges resolve successfully in the running Python 3.12.15 API image (including FastAPI 0.143.1, SQLAlchemy 2.1.4, psycopg 3.3.6 and `python-gvm` 26.11.1). There is no evidence from this repository that the host OS is older than Debian 13.

## Verification record

Verification run on Debian 13.7 / Python 3.13.5 / Node 20.19.2 / npm 9.2.0:

- `npm ci --no-audit --no-fund` and `npm update --no-audit --no-fund`: PASS; lockfile refresh changed 57 packages within existing semver ranges.
- `npx tsc -b`: PASS.
- `npx vitest run`: PASS, 16 files / 78 tests.
- `npm run build`: PASS with the existing Vite warning that the main JS chunk exceeds 500 kB.
- Temporary Python 3.13 virtual environment, `pip install -r requirements.txt`, and `tls_scan.py --config config/config.yaml --list-reports`: PASS.
- `python -m unittest -q test_tls_scanner`: PASS, 115 tests.
- `PYTHONPATH=. python -m unittest tests/engine/test_runner.py tests/engine/test_tls_checks.py tests/engine/test_tls_checks_integration.py tests/engine/test_tls_checks_lot2.py`: PASS, 170 tests / 1 skipped.
- The active Integrations VM API reports Python 3.12.15, OpenSSL 3.5.7, Nmap 7.95 and PostgreSQL 16.15; its Nginx is 1.27.5. Its Debian 13.7 host and running containers were inspected read-only.
- Docker build on the VM: PASS for the Debian 13 API image and Node 24 / Nginx 1.30.6 Trixie frontend image.
- Isolated Compose startup: PASS with separate `tls-scan-lst6` volumes and PostgreSQL 16 Alpine. PostgreSQL, API readiness and WebUI HTTPS healthchecks pass; worker and scheduler start. The existing `tls-scan` project and database volume were not changed.
- The first Compose startup exposed that the Debian Nginx image lacks the `wget` binary used by the Alpine healthcheck; the runtime image now installs `curl` and Compose probes the same local HTTPS page with curl.
- Before/after login captures at 1280×900 and 390px width are pixel-identical (0 changed pixels). See [desktop before](screenshots/lst6/before-desktop.png), [desktop after](screenshots/lst6/after-desktop.png), [mobile before](screenshots/lst6/before-mobile.png) and [mobile after](screenshots/lst6/after-mobile.png).

## Image sources

- Node [release schedule](https://nodejs.org/en/about/previous-releases) and [official Trixie image definition](https://github.com/nodejs/docker-node/blob/main/24/trixie-slim/Dockerfile).
- Nginx [official image](https://hub.docker.com/_/nginx) supports versioned Trixie tags; this project uses the stable 1.30 line.
- PostgreSQL [official tags](https://hub.docker.com/_/postgres/tags?name=16) include PostgreSQL 16 on Trixie, but this change deliberately keeps the existing 16 Alpine data path until an isolated restore test approves a base-image conversion.
