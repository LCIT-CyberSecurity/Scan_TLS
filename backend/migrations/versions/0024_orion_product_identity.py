"""Orion rebranding: record the product identity and free the new built-in trust store name.

The database holds no product name owned by the application: historical results, notifications, audit events and
administrator-entered values that mention "TLS Scan" are history or user data and stay untouched. The only conflict
the rebranding can create is a custom trust store already called "Orion Public Web PKI", now the reserved name of the
built-in store (scans would refuse the duplicate). Such a store is renamed "<name> (custom)"; stores are referenced by
id, so profiles and history are unaffected. Every rename is recorded so the downgrade restores the exact names.

Idempotent: a second run finds no conflicting store and keeps the existing record.
"""
import json
import uuid

import sqlalchemy as sa
from alembic import op

revision = "0024_orion_product_identity"
down_revision = "0023_endpoint_exposure_context"
branch_labels = None
depends_on = None

SETTING_KEY = "product_identity"
BUILTIN_NAME = "Orion Public Web PKI"
SUFFIX = " (custom)"
NAME_MAX = 120

settings = sa.table("system_settings", sa.column("key", sa.String), sa.column("value", sa.JSON))
stores = sa.table("trust_stores", sa.column("id", sa.Uuid), sa.column("name", sa.String))


def _record(connection) -> dict | None:
    value = connection.execute(sa.select(settings.c.value).where(settings.c.key == SETTING_KEY)).scalar_one_or_none()
    return json.loads(value) if isinstance(value, str) else value


def _free_name(connection, base: str) -> str:
    taken = {name.casefold() for name in connection.execute(sa.select(stores.c.name)).scalars()}
    stem = base[:NAME_MAX - len(SUFFIX) - 4]
    candidate, index = stem + SUFFIX, 2
    while candidate.casefold() in taken:
        candidate, index = f"{stem} ({index})", index + 1
    return candidate


def upgrade() -> None:
    connection = op.get_bind()
    record = _record(connection)
    renamed = list((record or {}).get("renamed_trust_stores", []))
    conflicts = connection.execute(sa.select(stores.c.id, stores.c.name)
                                   .where(sa.func.lower(stores.c.name) == BUILTIN_NAME.lower())).all()
    for store_id, name in conflicts:
        new_name = _free_name(connection, name)
        connection.execute(stores.update().where(stores.c.id == store_id).values(name=new_name))
        renamed.append({"id": str(store_id), "from": name, "to": new_name})
    value = {"product": "Orion", "previous_product": "TLS Scan", "renamed_trust_stores": renamed}
    if record is None:
        connection.execute(settings.insert().values(key=SETTING_KEY, value=value))
    elif record != value:
        connection.execute(settings.update().where(settings.c.key == SETTING_KEY).values(value=value))


def downgrade() -> None:
    connection = op.get_bind()
    record = _record(connection) or {}
    for entry in reversed(record.get("renamed_trust_stores", [])):
        connection.execute(stores.update().where(stores.c.id == uuid.UUID(entry["id"]), stores.c.name == entry["to"]).values(name=entry["from"]))
    connection.execute(settings.delete().where(settings.c.key == SETTING_KEY))
