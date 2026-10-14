# CrashTest authentication checks

Run these scripts on the integrations VM from a checkout of this branch. They keep test data and Docker resources
separate from the regular TLS Scan services.

```bash
tests/crashtest/test/test-entra.sh
tests/crashtest/test/test-google.sh
CRASHTEST_COMPOSE_PROJECT=tlsscan-crashtest tests/crashtest/test/test-openldap.sh
```

The Entra and Google scripts run the deterministic mock-OIDC tests in separate, disposable Docker Compose projects.
They cover claims, tenant/domain restrictions, state and role behavior; they do not contact Microsoft or Google and
do not prove that a real tenant or Workspace is configured correctly.

The OpenLDAP script exercises the running CrashTest stack: it temporarily selects its private LDAPS fixture,
checks diagnostics, signs in the fixture user, verifies the TLS Scan session and retained role, then restores the
authentication configuration that was active before the test. It does not print the fixture passwords. Start the
CrashTest first with `tests/crashtest/start.sh <vm-host>`; if it was started under a non-default Compose project,
set `CRASHTEST_COMPOSE_PROJECT` to that project name.

Logs from the Entra and Google mock runs are saved under the ignored `artifacts/` directory beside these scripts.
The OpenLDAP script prints concise pass/fail checks and leaves the pre-existing CrashTest stack running.
