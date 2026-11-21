# Secrets: design

How Orion keeps deployment credentials under Docker Compose (LST-25). Operating procedures (install, migration,
rotation, backup, checks) are in the [administrator guide](../admin/secrets.md).

## Goals and constraints

- No credential in clear in PostgreSQL, in `.env`, in a container environment variable, in an image, in Git, in a log,
  in an API response or in a CI artifact.
- Each container receives only the credentials it uses (least privilege); the WebUI receives none.
- No Vault and no ad hoc cryptography: Docker Compose file secrets on a protected host directory, plus the existing
  Fernet key for the few credentials an administrator enters in the WebUI.
- Existing installations keep their volumes, accounts and passwords: nothing is rotated or regenerated implicitly, and
  every migration step is explicit, verified and reversible.
- No change to the WebUI or to the business workflows.

## Where each secret lives

```
 host: ORION_SECRET_DIR (default ./data/secrets, outside Git)      mode 0710, group ORION_SECRET_GID
   ├── postgres_password, database_password, session_secret, …    mode 0440, owner deploying user, group ORION_SECRET_GID
   │
   │  docker compose "secrets:" (bind mount, read-only, per service)
   ▼
 container: /run/secrets/<name>  ──  read once at start-up by Settings (config.py) through ORION_<NAME>_FILE
```

- Each container runs with `group_add: ORION_SECRET_GID`, which is how a non-root process reads a `0440` file. Compose
  file secrets are bind mounts: the host mode and ownership apply unchanged inside the container.
- `.env` holds only non-sensitive settings and is kept `0600`. It is never loaded wholesale (`env_file` is not used):
  each service lists the variables it receives explicitly in `compose.yaml`.
- The database URL carries no password (`postgresql+psycopg://orion@postgres:5432/orion`). The backend reads
  `database_password` and adds it to the SQLAlchemy URL in memory; Alembic migrations do the same.
- Credentials entered in the WebUI (GMP password, LST-24; Microsoft Entra client secret, LST-36) are stored in
  PostgreSQL encrypted with Fernet under `greenbone_credential_key`. That key is a file secret, so a database dump alone
  cannot decrypt them.

## Secret × service matrix

| Secret file | api | worker | scheduler | postgres | webui | Used for |
|---|:-:|:-:|:-:|:-:|:-:|---|
| `postgres_password` | | | | ✔ | | PostgreSQL role password (`POSTGRES_PASSWORD_FILE`, read at first initialisation) |
| `database_password` | ✔ | ✔ | ✔ | | | Same value, used by the backend to connect |
| `session_secret` | ✔ | | | | | Signs web sessions and CSRF tokens |
| `local_admin_password` | ✔ | | | | | Optional initial local administrator password |
| `oidc_client_secret`, `google_client_secret` | ✔ | | | | | SSO (Entra or generic OIDC, Google) |
| `directory_client_secret`, `ldap_bind_password`, `google_directory_key.json` | ✔ | | | | | Directory lookups (Graph, LDAP/AD, Google) |
| `greenbone_password`, `greenbone_ca.pem`, `greenbone_client.crt`, `greenbone_client.key` | ✔ | ✔ | | | | OpenVAS / Greenbone GMP connection |
| `greenbone_credential_key` | ✔ | ✔ | | | | Fernet key for the credentials stored in the database |
| `smtp_password`, `graph_client_secret` | ✔ | ✔ | ✔ | | | E-mail notifications (SMTP or Microsoft Graph) |
| `snmp_v3_auth_key`, `snmp_v3_priv_key` | ✔ | ✔ | | | | Read-only SNMPv3 discovery |
| HTTPS certificate and key (`ORION_CERT_DIR`) | | | | | ✔ | TLS of the WebUI (mounted read-only) |

Why the boundaries are drawn there:

- The **scheduler** only queues runs and sends notifications. It runs with `ORION_SESSION_SECRET_REQUIRED=false`, so it
  starts without the session secret, and it never sees the identity-provider, Greenbone or SNMP credentials.
- The **worker** does not serve HTTP. It has neither the session secret nor the SSO and directory credentials, only
  what scans, imports and notifications use.
- The **WebUI** is static nginx. It has no `/run/secrets` and talks to the API only.
- The scan **subprocess** that the worker starts runs with a stripped environment and no database access.

Optional connectors that are not configured still have a file, left empty, so that Compose can mount it. An empty file
means "not configured", and the feature stays disabled.

## Reading and failure behaviour

`Settings` resolves each `ORION_<NAME>_FILE` at start-up through `_read_secret`:

- A missing, unreadable or wrongly permissioned file fails start-up with
  `Unable to read configured <label> file (<ErrorClass>)`. The message names the setting and the error class only,
  never the content.
- An empty `database_password` is refused, and so is a weak or development session secret in production.
- The background services start without the session secret. The API cannot.

For compatibility, a direct `ORION_<NAME>` value is still read when no file is configured, for development outside
Docker. `compose.yaml` never passes direct credential variables to a container, and the bootstrap moves any value left
in `.env` into files. Settings still read under a pre-rebranding `TLS_SCAN_*` name produce a start-up warning that
lists the variable names, never their values.

## Migration and rollback model

`bootstrap_orion-deployment.sh` owns the host side:

- **New install**: creates the directory and the files, generates the PostgreSQL password, the session secret and the
  credential key, and creates empty placeholders for the optional connectors.
- **Existing install with direct `.env` credentials**: lists what it will move and asks for confirmation (`--yes`
  accepts it explicitly). It then copies every value byte for byte with an atomic write, and blanks the direct values
  in `.env` only after the copy succeeds.
  - It refuses to overwrite a protected file whose content differs.
  - It refuses to invent a PostgreSQL password when a database volume already exists without its password file.
  - It refuses to continue when the two PostgreSQL password copies differ.
- **Rollback**: `rollback-secrets` writes the values back into `.env` for an older release that still reads direct
  variables. Nothing is rotated: the same credentials work in both directions.

## At rest and backups

- Compose file secrets are **not encrypted** on the host. Their protection is the host itself: file modes, group,
  disk encryption, administrator access. This limit is accepted and documented, since the ticket excludes Vault.
- The application backup (`bootstrap … backup`) contains the database dump and the `data` volume, never the secret
  directory, `.env` or the HTTPS key. Those are backed up **separately and encrypted** by the administrator.
- A database dump on its own exposes no credential. The credentials stored in it are Fernet tokens, unreadable without
  `greenbone_credential_key`.

## Verification

| Acceptance criterion | Evidence |
|---|---|
| AC01: inventory and minimisation plan | The matrix above. `test_compose_grants_file_secrets_only_to_consumers` keeps `compose.yaml` aligned with it |
| AC02: only the consumers receive a secret, no leak | `test_secret_files.py`: content never echoed, missing file, password absent from the URL, `.env.example` without values. Sandbox check of `/run/secrets` per container and of the environment variable names |
| AC03: existing installations preserved | `tests/bootstrap/run.sh`: migration declined, accepted, conflicting, rollback; secrets reused and never rotated; existing PostgreSQL volume without a password file |
| AC04: connectors and scans unchanged | Full backend suite on the test stack. Live connectors (OpenVAS, SSO/LDAP, SMTP, SNMP) depend on what each deployment provisions |
| AC05: operations, backup, rotation, restore test | [Administrator guide](../admin/secrets.md) |
