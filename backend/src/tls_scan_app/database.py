from __future__ import annotations

from pathlib import Path

from sqlalchemy import JSON, Engine, create_engine, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# JSONB on PostgreSQL (indexable, compact); plain JSON elsewhere (unit tests on SQLite).
JsonType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


def make_engine(database_url: str, password_file: str = "") -> Engine:
    """Build a DB engine, optionally reading its password from a protected mounted file.

    Keeping the URL password-free prevents Compose environment inspection and diagnostics from
    exposing the database credential. A direct URL remains supported for development and legacy
    deployments.
    """
    url = make_url(database_url)
    if password_file:
        try:
            password = Path(password_file).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as error:
            raise RuntimeError(f"Database password file is unavailable ({error.__class__.__name__})") from None
        if not password:
            raise RuntimeError("Database password file is empty")
        url = url.set(password=password)
    return create_engine(url, pool_pre_ping=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def database_is_ready(engine: Engine) -> bool:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 - readiness probe must never raise
        return False
