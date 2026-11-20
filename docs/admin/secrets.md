# Docker secret handling

WebUI deployment credentials are stored as host files under `ORION_SECRET_DIR` (default `./data/secrets`) and mounted only into services that consume them. The bootstrap script creates the directory with mode `0710`, sets protected files to `0440` and assigns the configured `ORION_SECRET_GID` (default: the deploying user's primary group). Only API, worker, scheduler, or PostgreSQL receive the exact files they need; the frontend receives none. Containers drop Linux capabilities and enable `no-new-privileges`.

| Secret file | Consumer | Purpose |
|---|---|---|
| `postgres_password` | PostgreSQL | Initial/ongoing PostgreSQL credential (`POSTGRES_PASSWORD_FILE`) |
| `database_password` | API, worker, scheduler | Copy of the DB password read into a SQLAlchemy URL at runtime |
| `session_secret` | API | Signed web sessions and CSRF |
| `local_admin_password` | API | Optional initial local-admin password |
| `oidc_client_secret`, `google_client_secret`, `directory_client_secret`, `ldap_bind_password` | API | Configured identity providers/directories |
| `greenbone_password`, `greenbone_ca.pem`, `greenbone_client.crt`, `greenbone_client.key` | API | Optional Greenbone GMP connection |
| `greenbone_credential_key` | API, worker | Key encrypting the credentials entered in the WebUI and stored in PostgreSQL: GMP password, Entra client secret |
| `smtp_password`, `graph_client_secret` | API, worker, scheduler as needed | Notifications |
| `snmp_v3_auth_key`, `snmp_v3_priv_key` | API, worker | Optional read-only SNMPv3 |
| `google_directory_key.json` | API | Optional Google directory lookup |

Non-secret settings remain explicit Compose environment values. `.env` is not loaded wholesale into containers and must not contain credential values. The database URL in container configuration has no password. Compose file secrets are host files, so protect the host, keep the secret directory outside source control, and encrypt separate backups of it.

## Migration from direct `.env` values

`bootstrap_orion-deployment.sh` detects legacy direct credential values and configured secret-file paths. It explains the migration and requires confirmation before copying them. It preserves the credential values, refuses conflicting existing copies, writes host files atomically, removes direct credentials from `.env`, and updates supported file-path settings. `--yes` explicitly accepts that migration. Review the resulting `data/secrets/` files and backup them securely with the deployment's recovery material.

The bootstrap refuses to invent a PostgreSQL password if a database volume already exists but its password file is missing. Restore the existing password file from a protected backup before continuing; do not rotate the database secret without coordinating PostgreSQL and the application.

For an intentional rollback to an older release that still reads direct `.env` secrets, run `./bootstrap_orion-deployment.sh --mode webui rollback-secrets`. This asks for confirmation, writes the existing values back to `.env`, and sets `.env` mode `0600`. Roll back code and Compose together, then remove the direct values again when returning to the file-secret release.

## Backup, restore, and rotation

The standard application backup includes the PostgreSQL dump and persistent application data, not the secret directory, `.env`, or TLS certificate key. Keep encrypted, access-controlled backups of those deployment files separately; `greenbone_credential_key` is required to read the GMP password and the Entra client secret stored encrypted in the database dump. A recovery set needs the matching database password, session key, provider credentials, certificate and private key as applicable. Test restoration in an isolated deployment before replacing a live environment.

To rotate the database password, coordinate the PostgreSQL role password and both `postgres_password` and `database_password` files while services are stopped, preserving a protected old copy for rollback. For identity-provider, SMTP, Graph, SNMP, and Greenbone credentials, update the provider and the relevant host file as one operational change, then recreate affected services. Never expose a secret in command-line arguments, logs, screenshots, or Jira comments.

See [installation](install.md) and [operations](operations.md) for the deployment procedures.
