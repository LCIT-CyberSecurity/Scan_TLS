"""Admin command line: python -m tls_scan_app.cli <command>"""
from __future__ import annotations

import argparse
import secrets
import sys

from sqlalchemy import select

from tls_scan_app.auth.passwords import hash_password
from tls_scan_app.config import get_settings
from tls_scan_app.database import make_engine, make_session_factory
from tls_scan_app.models import User


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tls_scan_app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("bootstrap", help="create the organisation row and the initial local administrator")
    reset = sub.add_parser("reset-admin-password", help="issue a new one-time password for the local administrator")
    reset.add_argument("--username", default=None)
    args = parser.parse_args(argv)
    settings = get_settings()
    factory = make_session_factory(make_engine(settings.database_url))
    with factory() as db:
        if args.command == "bootstrap":
            from tls_scan_app.services.bootstrap import ensure_bootstrap

            ensure_bootstrap(db, settings)
            print("bootstrap done")
            return 0
        username = args.username or settings.local_admin_username
        user = db.execute(select(User).where(User.issuer == "builtin:local", User.subject == username)).scalar_one_or_none()
        if user is None:
            print("no such local administrator", file=sys.stderr)
            return 1
        password = secrets.token_urlsafe(18)
        user.password_hash, user.must_change_password, user.active = hash_password(password), True, True
        db.commit()
        print(password)  # shown once, on the operator's terminal only
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
