import tls_scan_app.models  # noqa: F401 - registers the tables
from alembic import context
from tls_scan_app.config import get_settings
from tls_scan_app.database import Base, make_engine

config = context.config


def run() -> None:
    settings = get_settings()
    engine = make_engine(settings.database_url, settings.database_password_file)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()


run()
