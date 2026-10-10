# Installation (WebUI mode)

Prerequisites: Linux host with Docker + Compose plugin, `openssl`, outbound network access to the networks you
want to scan. The Standalone CLI needs none of this.

```bash
git clone <repo> && cd Scan_TLS
./bootstrap_tls-scan-deployment.sh install
```

The bootstrap:

1. creates `.env` from `.env.example` (never overwritten) and generates `POSTGRES_PASSWORD` and
   `TLS_SCAN_SESSION_SECRET`;
2. generates a **self-signed certificate** in `data/certs` if none exists — replace `fullchain.pem` /
   `privkey.pem` with your own for production;
3. builds the images, starts PostgreSQL, API (migrations run on start), worker, scheduler and the HTTPS web UI;
4. waits for health checks and prints the **one-time initial administrator password** (generated, unique,
   must be changed at first sign-in; the file holding it is removed after display).

Edit `.env` first if needed: `TLS_SCAN_PUBLIC_BASE_URL` (used for SSO redirects and e-mail links),
`TLS_SCAN_HTTPS_PORT`, scan limits, OIDC settings.

| Command | Purpose |
|---|---|
| `install` | first installation (idempotent) |
| `update` | `git pull --ff-only`, **backup first**, rebuild, migrate, restart — data preserved |
| `status` | containers + health |
| `backup [dir]` / `restore <file>` | PostgreSQL dump + reports; restore needs the typed word `RESTORE` |
| `reset-admin` | new one-time password for the local administrator |
| `logs [service]` | technical logs |
| `reinstall` | rebuild, **keep data** |
| `uninstall` | remove containers/images; volumes are kept unless you also type `DELETE-ALL-DATA` |

The first administrator is local. Configure SSO afterwards ([Entra ID](../integrations/entra-sso.md)), then
promote SSO users in *Administration → Users*. New SSO users get the role of `TLS_SCAN_OIDC_DEFAULT_ROLE`
(default `USER`); the identity provider never grants roles.

Upgrade/rollback: always take a `backup` first (the `update` command does). Migrations are forward-only; to roll
back, restore the backup taken before the update.
