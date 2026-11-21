# Docker secrets: administrator guide

Day-to-day handling of Orion's deployment credentials: where they are, how they are created, migrated, rotated, backed
up, restored and checked. The [design document](../architecture/secrets.md) explains the choices and lists which
container receives which secret. Commands assume the deployment directory (where `compose.yaml` and `.env` are) and a
deploying user who belongs to `ORION_SECRET_GID`.

> Never put a secret on a command line, in a shell history, a log, a screenshot, a ticket or a pull request. The
> procedures below read values from a prompt (`read -rs`) or from a generator, straight into the protected file.

## Layout and permissions

| Item | Location | Mode | Contents |
|---|---|---|---|
| Secret directory | `ORION_SECRET_DIR`, default `./data/secrets` | `0710`, group `ORION_SECRET_GID` | One file per credential (see the [matrix](../architecture/secrets.md#secret--service-matrix)) |
| Secret files | `data/secrets/<name>` | `0440`, owner deploying user, group `ORION_SECRET_GID` | The value only, no trailing newline needed. An empty file means "not configured" |
| `.env` | deployment directory | `0600` | Non-sensitive settings and `ORION_SECRET_DIR` / `ORION_SECRET_GID`, never a credential value |
| HTTPS certificate | `ORION_CERT_DIR`, default `./data/certs` | key `0600` | Mounted read-only in the WebUI only |

`ORION_SECRET_GID` defaults to the deploying user's primary group. Every backend container runs with that group added,
which is how it reads a `0440` file. If you change the group, change it on the directory and on every file as well.

## New installation

`./bootstrap_orion-deployment.sh --mode webui install` creates the directory and its files:

- **Generated**: the PostgreSQL password (`postgres_password`, copied to `database_password`), the session secret and
  the credential key (`greenbone_credential_key`).
- **Created empty**: one placeholder per optional connector (SSO, directories, Greenbone, SMTP, Graph, SNMPv3).
- `.env` receives no credential.

To enable a connector, put its credential in the matching file (see [Set or change a connector credential](#set-or-change-a-connector-credential)),
set its non-sensitive settings in `.env` (issuer, client ID, host, user…), then run
`./bootstrap_orion-deployment.sh --mode webui redeploy`.

## Existing installation: migrating from `.env` values

Installations made before LST-25 may still have credentials in `.env`: `POSTGRES_PASSWORD`, `ORION_*_SECRET`,
`*_PASSWORD`, or the `TLS_SCAN_*` equivalents. They may also have `*_FILE` paths pointing elsewhere on the host.

1. Take an application backup and an [encrypted secret backup](#encrypted-backup-of-the-secrets) (it includes the
   current `.env`).
2. Run `./bootstrap_orion-deployment.sh --mode webui update`. The migration also runs on `install` and `redeploy`.
3. The script lists what it will move and asks for confirmation; `--yes` gives that confirmation explicitly. It copies
   each value **unchanged** into `data/secrets/`, protects the files, and only then blanks the values in `.env`.
   Nothing is rotated.
4. Check the result with [Checking that nothing leaks](#checking-that-nothing-leaks), and test a sign-in and a scan.

Cases where the script stops on purpose, without changing anything:

| Message (French, from the script) | Meaning | What to do |
|---|---|---|
| « La valeur de … diffère déjà du fichier protégé … » | `.env` and the existing file hold different values | Decide which one is right, fix the other one, run again |
| « Un volume PostgreSQL existe mais aucun secret postgres_password n'est disponible » | The database exists but its password file is missing | Restore `postgres_password` from your secret backup. Never let a new one be generated |
| « Les copies de mot de passe PostgreSQL ne correspondent pas » | `postgres_password` ≠ `database_password` | Restore the right value into both files |
| « Migration refusée » | You answered no | `.env` and the files are left as they were |
| « Le fichier protégé configuré pour … est absent » | `.env` points to `/run/secrets/<name>` but the host file is missing | Restore the file from backup |

**Rollback** to a release that still reads direct `.env` values: run
`./bootstrap_orion-deployment.sh --mode webui rollback-secrets`. After a confirmation, it writes the same values back
into `.env` (mode `0600`). Roll back the code and `compose.yaml` together. When you return to the current release,
`update` migrates the values again.

## Set or change a connector credential

Write the new value through a prompt into a temporary file in the same directory, then move it in place. The file
keeps its `0440` mode and its group:

```bash
cd data/secrets
read -rsp "New value: " V; echo
umask 077; printf '%s' "$V" > .smtp_password.new; unset V
chgrp "$(grep -E '^ORION_SECRET_GID=' ../../.env | cut -d= -f2)" .smtp_password.new
chmod 0440 .smtp_password.new
cp -p smtp_password ../.smtp_password.old    # rollback copy, kept with the same protection
mv -f .smtp_password.new smtp_password
cd ../.. && docker compose up -d --force-recreate api worker scheduler
```

A file secret is a bind mount of one inode, so replacing the file requires recreating the containers that use it (see
the matrix): `api` for SSO and directories; `api worker` for Greenbone and SNMP; `api worker scheduler` for SMTP and
Graph. Change the value at the provider and in the file as one operation, check the feature, then delete the `.old`
copy.

## Rotation

| Secret | Procedure | Effect |
|---|---|---|
| Connector credentials (SSO, LDAP, Graph, SMTP, SNMP, Greenbone) | Change at the provider, then [set the file](#set-or-change-a-connector-credential) and recreate the consumers | None for users |
| `session_secret` | Write a new value (`openssl rand -hex 32` piped straight into the file, mode `0440`), then `docker compose up -d --force-recreate api` | Every user must sign in again |
| PostgreSQL password | Cold procedure below | Short interruption |
| `greenbone_credential_key` | Do **not** rotate it routinely. It decrypts the GMP password and the Entra client secret stored in the database. If it is lost or replaced, re-enter both in the WebUI. The Entra sign-in falls back to `oidc_client_secret` in the meantime | Connectors stored in the database stop until re-entered |

**PostgreSQL password (cold rotation).** `POSTGRES_PASSWORD_FILE` is read only when the database is first created, so
the role must be changed inside PostgreSQL:

1. Take an application backup and an encrypted secret backup.
2. `docker compose stop api worker scheduler`. PostgreSQL keeps running.
3. `docker compose exec postgres psql -U orion -d orion -c '\password orion'` asks for the new password twice, at a
   prompt; nothing appears in the history. Replace `orion` with your `ORION_DB_USER` / `ORION_DB_NAME` if you changed them.
4. Write the same value into **both** `postgres_password` and `database_password`, as in
   [Set or change a connector credential](#set-or-change-a-connector-credential), keeping `.old` copies.
5. `docker compose up -d`, then check `/healthz` and a sign-in.

To roll back, set the old password with `\password`, put the `.old` copies back, and run `docker compose up -d`.

## Encrypted backup of the secrets

The application backup (`bootstrap … backup`) holds the database dump and the `data` volume. It **never** includes
`data/secrets/`, `.env` or the HTTPS key, so those need their own encrypted backup, kept apart from the application
backups:

```bash
umask 077
tar -czf - .env data/secrets data/certs \
  | gpg --symmetric --cipher-algo AES256 -o "/secure/location/orion-secrets-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.gpg"
```

- Store the passphrase separately, in your password manager.
- Make a new backup after every rotation or connector change.
- Any encryption tool your organisation approves can replace `gpg`.

A database dump without `greenbone_credential_key` is safe to store, but the credentials entered in the WebUI cannot be
recovered from it.

## Restoring

1. Decrypt into a new directory, readable by you only:
   ```bash
   mkdir -m 700 restore && gpg -d orion-secrets-….tar.gz.gpg | tar -xzf - -C restore
   ```
2. Copy `restore/data/secrets/` to `ORION_SECRET_DIR` and `restore/.env` to the deployment directory. Then set the
   modes (`0710` for the directory, `0440` for the files, `0600` for `.env`) and the group (`ORION_SECRET_GID`).
3. On a new host: `install`, then `restore <application archive>`. The database password in `postgres_password` must
   be the one the restored database was created with.
4. Delete `restore/`.

**Restore test.** Do it at least once per backup scheme, in a scratch directory or an isolated deployment, never over
the live one. Decrypt the archive and check that it lists the expected files (`tar -tzf`). Then compare each file with
the live one using `cmp -s`, which prints nothing but the result, and never with `cat` or `diff`.

## Checking that nothing leaks

These checks print names, never values:

```bash
# which secrets each container sees — must match the matrix; the webui sees none
for s in api worker scheduler webui postgres; do
  echo "$s: $(docker compose exec -T $s sh -c 'ls /run/secrets 2>/dev/null' | tr '\n' ' ')"
done
# no credential in container environments: only *_FILE paths may appear
for s in api worker scheduler webui postgres; do
  docker inspect "$(docker compose ps -q $s)" --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | cut -d= -f1 | grep -E 'PASSWORD|SECRET|TOKEN|_KEY$' | grep -vE '_FILE$|_REQUIRED$|_SECRETS_DIR$|^GPG_KEY$'
done
# no direct credential left in .env (expected output: 0), and the expected modes
grep -Ec '^(POSTGRES_PASSWORD|(ORION|TLS_SCAN)_[A-Z_]*(PASSWORD|SECRET|_KEY))=[^[:space:]]+' .env
stat -c '%a %n' .env data/secrets data/secrets/*
```

`GPG_KEY` is the public release-signing key ID that the Python base image sets, not a secret. Also check that
`docker compose config` shows `file:` paths under `secrets:` and no value, and that the database URL has no password
(`…://orion@postgres:5432/orion`).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| A container exits with `Unable to read configured <label> file (PermissionError)` | Wrong group or mode, or `ORION_SECRET_GID` differs from the file's group | `chgrp <gid>` and `chmod 0440` on the file, `0710` on the directory |
| Same message with `FileNotFoundError` | File missing on the host | Restore it, or create it empty if the connector is unused |
| `Refusing to start in production: ORION_SESSION_SECRET is empty, short…` | `session_secret` empty or weak | Write a value of at least 32 random characters, then recreate `api` |
| `docker compose up` fails because a secret file does not exist | A placeholder is missing (for example after a manual copy) | `./bootstrap_orion-deployment.sh --mode webui redeploy` recreates the empty placeholders |
| The API cannot connect to PostgreSQL after a restore | `postgres_password` / `database_password` do not match the restored database | Restore the matching value into both files, or set it with `\password` |
