"""Create an AegisGate user from the command line (initial administrator setup).

    python scripts/create_user.py --username admin --role security_admin

The password is asked for interactively and never appears in the command line,
the repository or the audit log.
"""
import argparse
import getpass
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app import passwords  # noqa: E402
from app.auth_models import ROLES, UserRecord  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.db_models import AuditLogRecord  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an AegisGate user.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", required=True, choices=ROLES)
    args = parser.parse_args()

    username = args.username.strip().lower()
    if re.fullmatch(r"[a-z0-9][a-z0-9._@-]{2,63}", username) is None:
        print("Username must be 3-64 characters: lowercase letters, digits, . _ @ -")
        return 2

    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Repeat password: "):
        print("Passwords do not match.")
        return 2
    try:
        passwords.validate_new_password(password)
    except ValueError as error:
        print(error)
        return 2

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        if db.get(UserRecord, username) is not None:
            print(f"User '{username}' already exists.")
            return 1
        now = datetime.now(UTC)
        db.add(UserRecord(username=username, password_hash=passwords.hash_password(password),
                          role=args.role, is_active=True, created_at=now, updated_at=now,
                          last_login_at=None))
        db.add(AuditLogRecord(occurred_at=now, actor="local-cli", action="user_created",
                              target_type="user", target_id=username, details_json={"role": args.role}))
        db.commit()
    print(f"User '{username}' created with role {args.role}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
