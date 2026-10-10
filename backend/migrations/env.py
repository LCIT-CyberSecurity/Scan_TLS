from alembic import context
from sqlalchemy import create_engine

import tls_scan_app.models  # noqa: F401 - registers the tables
from tls_scan_app.config import get_settings
from tls_scan_app.database import Base

config = context.config


def run() -> None:
    engine = create_engine(get_settings().database_url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()


run()
