# Installation

`bootstrap_tls-scan-deployment.sh` installs TLS Scan in one of **two independent modes**. Run it without
arguments for the interactive menu (French), or give a mode and a command for automation.

| | **Standalone** | **WebUI (Docker)** |
|---|---|---|
| What | the historical command-line engine | API + PostgreSQL + worker + scheduler + HTTPS web UI |
| Needs on the host | Python 3 (see `requires-python`), Nmap, `venv` | Docker + Compose plugin, `openssl` — nothing else |
| Installed in | `.venv/` of the repository | Docker Compose project `tls-scan` (images, containers, volumes) |
| Configuration | YAML files in `config/` | PostgreSQL |

The two modes can live on the same machine and never touch each other: a Standalone operation does not call Docker,
a WebUI operation does not touch `.venv/`, and neither synchronises or migrates data into the other. The CrashTest
(`tests/crashtest`) stays separate: the bootstrap refuses its project name (`*crashtest*`, `*e2e*`, `tlsscan-test*`)
and its image tag, and never seeds demonstration data.

```text
./bootstrap_tls-scan-deployment.sh                         # menu: [1] Standalone  [2] WebUI  [0] Quit
./bootstrap_tls-scan-deployment.sh --mode standalone install
./bootstrap_tls-scan-deployment.sh --mode webui install
./bootstrap_tls-scan-deployment.sh install                 # historical form: the WebUI
```

Each mode has its own menu (state, version, branch; `[0]` returns to the mode choice). Operations print numbered steps
(`[3/9] Fichier .env et secrets ... OK`, `ÉCHEC`, `IGNORÉ`); the technical output of a step is shown only when it fails.

## Standalone mode

```bash
git clone <repo> && cd Scan_TLS
./bootstrap_tls-scan-deployment.sh --mode standalone install
```

Steps: prerequisites (Python ≥ `requires-python`, `venv`, Nmap) → virtualenv `.venv` (reused if present) → `pip install -r
requirements.txt` → the CLI runs → `config/config.yaml` is validated (every report with `--dry-run`: no Nmap, no network). **No
scan is launched.** Missing system packages are listed; they are installed (apt/dnf/yum/zypper, with `sudo`) only if you
answer yes to the command shown. The profile `pqc` needs OpenSSL 3.5+ (a note is printed otherwise).

| Command | Purpose |
|---|---|
| `install` | create or reuse `.venv`, install the dependencies, verify (idempotent) |
| `update` | Git checks, fast-forward, refresh the dependencies, verify. `config/`, `logs/` and `scan_reports/` are never touched |
| `status` (`verify`) | verify the installation (dependencies, CLI, YAML) |
| `reinstall` | delete and recreate `.venv` only (typed confirmation `REINSTALLER`) |
| `uninstall` | delete `.venv` (typed `DESINSTALLER STANDALONE`); `logs/` and `scan_reports/` only if you also ask for it (typed `SUPPRIMER MES FICHIERS`). The Git repository and `config/` always stay |

## WebUI mode

Prerequisites: Linux host with Docker, the Compose plugin and `openssl`, outbound network access to the networks you want to
scan. Python, Nmap, Node.js and PostgreSQL are **never** installed on the host: they live in the images.

```bash
git clone <repo> && cd Scan_TLS
./bootstrap_tls-scan-deployment.sh --mode webui install
```

The installation:

1. checks Docker, the daemon and Compose; 2. checks the project name and that the HTTPS/HTTP ports are free;
3. creates `.env` from `.env.example` if absent (**never overwritten**) and generates only the secrets that are empty
   (`POSTGRES_PASSWORD`, `TLS_SCAN_SESSION_SECRET`; mode 600). An empty `POSTGRES_PASSWORD` next to an existing database
   volume is refused: a new password would lock the data away;
4. prepares the HTTPS certificate: existing files are kept; a self-signed one is generated only if **both** files are
   absent (`data/certs`); a missing file, a certificate/key mismatch is a failure (nothing is replaced); an expired or
   soon-to-expire certificate is reported; loose key permissions are tightened to 600;
5. validates the Compose configuration, builds the images, starts the containers (`up --wait`);
6. verifies the PostgreSQL migrations (the API runs `alembic upgrade head` at start) and the health of the five services;
7. prints the URL and the initial administrator: `admin` / `SecretPassword` (deployment default, same convention as
   LCIT-Sign). **It must be changed at first sign-in**; `TLS_SCAN_LOCAL_ADMIN_PASSWORD` overrides the default at first start.

Edit `.env` first if needed: `TLS_SCAN_PUBLIC_BASE_URL` (SSO redirects and e-mail links), `TLS_SCAN_HTTPS_PORT`, scan limits, OIDC.

| Command | Purpose |
|---|---|
| `install` | first installation (idempotent: `.env`, certificates and data are kept) |
| `update` (`redeploy`) | Git checks, **verified backup first**, fast-forward when a new version exists, rebuild, migrations, health. Data preserved |
| `status` (`verify`) | state, version, branch, services, health |
| `backup [dir]` | one archive `tls-scan-backup-<UTC>.tar.gz`: `db.dump` (`pg_dump -Fc`), `data.tar` (the data volume: reports, logs), `SHA256SUMS`, `MANIFEST.txt`; verified before it is kept; default `./backups` (override `TLS_SCAN_BACKUP_DIR`) |
| `restore <archive>` | verifies the sums and the dump, takes a safety backup, then (typed `RESTAURER`) replaces the database and the data |
| `reset-admin [--default]` | new random one-time password for the local administrator (`--default`: `SecretPassword`, change forced) |
| `logs [service]` | follow the technical logs (`api`, `worker`, `scheduler`, `postgres`, `webui`) |
| `reinstall` | **from scratch**: backup, typed `REINSTALLER`, then the project's containers **and volumes** are removed and rebuilt. `.env`, certificates and backups are kept. The database ends with the local administrator only |
| `uninstall` | removes containers and images (typed `DESINSTALLER TLS SCAN`). Data volumes, `.env`, certificates and backups are kept unless you answer yes to each question; deleting data needs a further typed `SUPPRIMER LES DONNEES` and a backup |

Three operations are distinct: **redeploy** (`update`) rebuilds and restarts without deleting anything; **reinstall** starts again
from an empty database after a backup; **uninstall** removes the components and asks separately about the data.
The WebUI only ever touches the Docker project `TLS_SCAN_PROJECT` (default `tls-scan`). Images are never force-removed
(they may be shared with another project using the same tag).

## Updates and Git

`update` never changes your branch and never resets, cleans or force-merges anything. It refuses: a dirty working tree
(`git status`), a detached HEAD, a branch without upstream, a diverged branch. A branch only *ahead* of its upstream has nothing
to pull and is redeployed after a question. On a development branch (`feature/…`) the upstream of that branch is used —
`main` is never selected automatically. `--no-git` redeploys the local code as is (also for a tree that is not a Git repository).

## Non-interactive use and safety

* `--mode standalone|webui` selects the mode; without a mode the historical commands address the WebUI.
* Destructive operations (`restore`, `reinstall`, `uninstall`, Standalone `reinstall`/`uninstall`) are **cancelled** without a
  terminal unless `--yes` is given. `--yes` answers the questions and the typed confirmations; backups stay on by default
  (`--no-backup` is explicit); data is deleted only with `--delete-data`.
* Exit codes: `0` done · `1` failure or refusal · `2` usage error · `3` cancelled, nothing modified.
* Secrets are written to `.env` (mode 600) and never printed or logged; the technical log of a run is a private temporary file.
* `.env` and the HTTPS certificate are **not** in backups: keep them in your own secret backup.

The first administrator is local. Configure SSO afterwards ([Entra ID](../integrations/entra-sso.md)), then
promote SSO users in *Administration → Users*. New SSO users get the role of `TLS_SCAN_OIDC_DEFAULT_ROLE`
(default `USER`); the identity provider never grants roles.

Upgrade/rollback: always take a `backup` first (the `update` command does). Migrations are forward-only; to roll
back, restore the backup taken before the update.
