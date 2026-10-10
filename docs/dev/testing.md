# Tests

All tests run on the integration VM in containers (nothing is installed on the development machine).

| What | Command | Notes |
|---|---|---|
| Engine unit tests (115 legacy + runner) | `python3 -m unittest -q test_tls_scanner` and `PYTHONPATH=. python3 -m unittest tests/engine/test_runner.py` | plain Python, existing venv |
| Backend (unit, API, permissions, security, concurrency, dedup, cancel, schedules, comparison, SSO mock, SMTP, retention, restart recovery) | `ops/dev/run-tests.sh [pytest args]` | isolated project `tlsscan-test`: PostgreSQL (tmpfs), api, worker, scheduler, lab TLS target, mock OIDC, SMTP sink. No published ports. |
| Timeout path | `TEST_MAX_DURATION=15 ops/dev/run-tests.sh tests/backend/test_reliability.py` | stack started with a 15 s limit |
| Frontend types + unit + build | `ops/dev/frontend.sh` | Node container |
| E2E (Playwright) | start the CrashTest, then see [crashtest](crashtest.md) | roles, scan flow, i18n, SSO mock |
| Standalone non-regression | `tests/regression/run.sh [base-commit]` | runs the baseline engine and the current one on the lab with the same YAML and diffs every export |
| Post-deployment smoke | `docker compose exec -T api python - < tests/smoke/smoke.py` | see the script header |

**Milestone test** (`tests/backend/test_milestone.py`): a scan configured through the API on a lab target is run by the
real worker with the historical engine, persisted, reported, downloaded as an AUDITOR, and its CSV is compared line by
line with the Standalone CLI's CSV for the same target and policy.

Active network tests only ever target the lab container (`tests/lab`: modern TLS, legacy CBC suites, expired
certificate, certificate expiring in 10 days, self-signed chain, plain HTTP, closed/unreachable ranges).

Not covered yet: PQC profile (needs an OpenSSL ≥ 3.5 image), real Entra ID, LDAP/Graph, load tests, a Playwright run in CI.
