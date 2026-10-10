# Contributing

* Branch from `main`; WebUI work lives on `feature/webui-v1`. One coherent commit per increment.
* **Do not change engine behaviour** (`tls_scanner/`) without a test and a note in `docs/limitations.md → Engine
  changes`. Run `tests/regression/run.sh` after any engine change: all exports must stay identical.
* Backend: Python 3.12, FastAPI, SQLAlchemy 2, Alembic. New table or column → new Alembic revision
  (`alembic revision --autogenerate` inside the api container). Enforce permissions in the API with
  `require_role` + owner checks; add a case to `test_permissions.py`. Never log secrets (use `services/logs.scrub_text`).
* Frontend: add every user-visible string to `src/i18n/en.ts`, `fr.ts`, `de.ts` (the type system and
  `__tests__/i18n.test.ts` fail if a language is missing a key). Use the design tokens (CSS variables) rather than
  literal colours.
* No fixtures, demo passwords or fake data outside `tests/` (CrashTest only).
* Reuse before writing: LCIT-Sign for patterns (sessions, OIDC, notifications); keep the code GPL-3.0-compatible.
