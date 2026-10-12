# Tests

All tests run on the integration VM in containers (nothing is installed on the development machine).

| What | Command | Notes |
|---|---|---|
| Engine unit tests (115 legacy + runner) | `python3 -m unittest -q test_tls_scanner` and `PYTHONPATH=. python3 -m unittest tests/engine/test_runner.py` | plain Python, existing venv |
| Backend (unit, API, permissions, security, login throttle, concurrency, dedup, cancel, schedules, comparison, SSO mock, SMTP + Graph mock, directory (OpenLDAP + Graph mock), branding, PQC, retention, restart recovery) | `ops/dev/run-tests.sh [pytest args]` (on the VM) or `ops/dev/test-stack.sh [pytest args]` (any Docker host, used by CI) | isolated project `tlsscan-test`: PostgreSQL (tmpfs), api, worker, scheduler, lab TLS target (Debian 13 / OpenSSL 3.5), mock OIDC, mock Graph, OpenLDAP, SMTP sink. No published ports. |
| Bootstrap script (menu, both modes, update/Git, backup/restore, reinstall/uninstall, isolation, legacy commands) | `tests/bootstrap/run.sh` (plain Bash; Docker is faked, Git is real, no network) | throw-away sandboxes; also `bash -n` and ShellCheck when installed |
| External API and MCP (switches, per-user authorisation, key lifecycle and hashing, expiry, REST/MCP/session separation, roles, read-only, OpenAPI scope, rate limit, Host/Origin, official MCP client) | `ops/dev/run-tests.sh tests/backend/test_external_access.py` | same stack as above |
| DNS discovery (pure logic, roles, worker) | `ops/dev/run-tests.sh tests/backend/test_discovery.py` | same stack |
| Complementary TLS checks: engine units (contract, SAN matching, OCSP verification with generated certificates and responses, parsers, scripted raw TLS servers, config, report isolation) | `ops/dev/run-tests.sh tests/engine` | no network except loopback; part of the backend image |
| Complementary TLS checks against real servers (lab nginx ports 8450-8456, `openssl s_server` variants, OpenSSL as reference tool) and end to end (profile → worker → storage → API → reports, grade and findings identical with and without the checks) | `ops/dev/run-tests.sh tests/backend/test_tls_checks_lab.py tests/backend/test_tls_checks_api.py` | same stack |
| Frontend components (global switches, key management and one-time key dialog) | `ops/dev/frontend.sh` (vitest, `src/__tests__/external-access.test.tsx`) | node container |
| Timeout path | `TEST_MAX_DURATION=15 ops/dev/run-tests.sh tests/backend/test_reliability.py` | stack started with a 15 s limit |
| Frontend types + unit + build | `ops/dev/frontend.sh` | Node container |
| E2E (Playwright) | start the CrashTest, then see [crashtest](crashtest.md) | roles, scan flow, i18n, SSO mock |
| Standalone non-regression | `tests/regression/run.sh [base-commit]` (VM) or `tests/regression/compare.sh` with the baseline tree in `.regression-base` (any Docker host) | runs the baseline engine and the current one on the lab with the same YAML and diffs every export |
| Post-deployment smoke | `docker compose exec -T api python - < tests/smoke/smoke.py` | see the script header |

**Milestone test** (`tests/backend/test_milestone.py`): a scan configured through the API on a lab target is run by the
real worker with the historical engine, persisted, reported, downloaded as an AUDITOR, and its CSV is compared line by
line with the Standalone CLI's CSV for the same target and policy.

Active network tests only ever target the lab container (`tests/lab`: modern TLS, legacy CBC suites, expired
certificate, certificate expiring in 10 days, self-signed chain, plain HTTP, closed/unreachable ranges).

Lab ports for the complementary checks: 8450 / 8451 stapled OCSP response good / revoked (static files, test CA), 8452 SAN mismatch,
8453 wildcard `*.lab.example`, 8454 DHE with 1024-bit parameters, 8455 DHE ffdhe2048 + ffdhe2048 group, 8456 single ECDHE group (secp384r1).
Behaviours nginx cannot be told to have (client-initiated renegotiation accepted/refused, no EMS) use `openssl s_server` started by the test.
Not reproducible with a current OpenSSL, therefore covered by scripted servers in `tests/engine` only: negotiated compression, missing RFC 5746, missing SCSV protection.

Active tests include the PQC profile (lab ports 8447 = X25519MLKEM768, 8448 = classical).

Not covered yet: a real Entra ID tenant, load tests, running the CI workflow on GitHub, Playwright inside CI.
