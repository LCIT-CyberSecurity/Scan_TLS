import os

import orion_app.models  # noqa: F401 - registers the tables
from alembic import context
from orion_app.config import ENV_PREFIX, LEGACY_ENV_PREFIX, get_settings
from orion_app.database import Base, make_engine

config = context.config

# Migrations already applied in the field are never edited, and some read TLS_SCAN_* directly (0011): expose each ORION_*
# variable under its legacy name too, for this process only, unless the legacy name is set itself.
for _name, _value in list(os.environ.items()):
    if _name.startswith(ENV_PREFIX):
        os.environ.setdefault(LEGACY_ENV_PREFIX + _name[len(ENV_PREFIX):], _value)


def run() -> None:
    settings = get_settings()
    engine = make_engine(settings.database_url, settings.database_password_file)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()


run()
