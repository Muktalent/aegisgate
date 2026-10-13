import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = PROJECT_ROOT / "backend" / "app" / "aegisgate.db"
BACKUP_ROOT = PROJECT_ROOT / "backups" / "manual_checks"


def connect_read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(
        f"{path.resolve().as_uri()}?mode=ro",
        uri=True,
        timeout=30,
    )


def check_integrity(connection: sqlite3.Connection) -> None:
    results = [
        row[0]
        for row in connection.execute("PRAGMA integrity_check")
    ]

    if results != ["ok"]:
        raise RuntimeError(f"Integrity check failed: {results}")

    foreign_key_errors = connection.execute(
        "PRAGMA foreign_key_check"
    ).fetchall()

    if foreign_key_errors:
        raise RuntimeError(
            f"Foreign key check failed: {foreign_key_errors}"
        )


def table_counts(connection: sqlite3.Connection) -> dict[str, int]:
    names = [
        row[0]
        for row in connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        )
    ]

    counts = {}

    for name in names:
        quoted_name = '"' + name.replace('"', '""') + '"'
        counts[name] = connection.execute(
            f"SELECT COUNT(*) FROM {quoted_name}"
        ).fetchone()[0]

    return counts


def logical_digest(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()

    for statement in connection.iterdump():
        digest.update(statement.encode("utf-8"))
        digest.update(b"\n")

    return digest.hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def main() -> None:
    if not SOURCE_PATH.is_file():
        raise FileNotFoundError(
            f"Source database does not exist: {SOURCE_PATH}"
        )

    started_at = datetime.now(UTC)
    check_id = (
        started_at.strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )

    check_dir = BACKUP_ROOT / check_id
    check_dir.mkdir(parents=True, exist_ok=False)

    backup_path = check_dir / "backup.db"
    restored_path = check_dir / "restore_test.db"

    with closing(connect_read_only(SOURCE_PATH)) as source:
        with closing(sqlite3.connect(backup_path)) as backup:
            source.backup(backup)

    with closing(connect_read_only(backup_path)) as backup:
        check_integrity(backup)
        backup_counts = table_counts(backup)
        backup_logical_hash = logical_digest(backup)

        with closing(sqlite3.connect(restored_path)) as restored:
            backup.backup(restored)

    with closing(connect_read_only(restored_path)) as restored:
        check_integrity(restored)
        restored_counts = table_counts(restored)
        restored_logical_hash = logical_digest(restored)

    if backup_counts != restored_counts:
        raise RuntimeError("Restored table counts do not match backup.")

    if backup_logical_hash != restored_logical_hash:
        raise RuntimeError("Restored logical content does not match backup.")

    completed_at = datetime.now(UTC)

    report = {
        "status": "verified",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "duration_seconds": (
            completed_at - started_at
        ).total_seconds(),
        "source_database": str(SOURCE_PATH.relative_to(PROJECT_ROOT)),
        "backup_file": backup_path.name,
        "restore_test_file": restored_path.name,
        "backup_sha256": file_digest(backup_path),
        "restored_sha256": file_digest(restored_path),
        "logical_content_sha256": backup_logical_hash,
        "integrity_check": "ok",
        "foreign_key_check": "ok",
        "backup_table_counts": backup_counts,
        "restored_table_counts": restored_counts,
        "logical_content_matches": True,
        "production_database_overwritten": False,
    }

    report_path = check_dir / "verification.json"
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    print(
        "\nVerification directory:",
        check_dir.relative_to(PROJECT_ROOT),
    )


if __name__ == "__main__":
    main()