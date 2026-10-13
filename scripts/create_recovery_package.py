import hashlib
import json
import shutil
import sqlite3
import subprocess
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_PATH = PROJECT_ROOT / "backend" / "app" / "aegisgate.db"
ASSETS_PATH = PROJECT_ROOT / "data" / "assets.json"
OUTPUT_ROOT = PROJECT_ROOT / "backups" / "recovery_packages"

CONFIGURATION_NAMES = [
    "AEGIS_ENVIRONMENT",
    "AEGIS_JWT_SECRET",
    "AEGIS_AUDIT_HMAC_KEY",
    "AEGIS_JWT_ALGORITHM",
    "AEGIS_ACCESS_TOKEN_EXPIRE_MINUTES",
    "AEGIS_INGESTOR_USERNAME",
    "AEGIS_INGESTOR_PASSWORD",
    "AEGIS_SOC_USERNAME",
    "AEGIS_SOC_PASSWORD",
    "AEGIS_ADMIN_USERNAME",
    "AEGIS_ADMIN_PASSWORD",
]

SENSITIVE_CONFIGURATION_NAMES = [
    "AEGIS_JWT_SECRET",
    "AEGIS_AUDIT_HMAC_KEY",
    "AEGIS_INGESTOR_PASSWORD",
    "AEGIS_SOC_PASSWORD",
    "AEGIS_ADMIN_PASSWORD",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def git_output(*arguments: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    return result.stdout.strip()


def validate_database(path: Path) -> dict[str, int]:
    with closing(
        sqlite3.connect(
            f"{path.resolve().as_uri()}?mode=ro",
            uri=True,
            timeout=30,
        )
    ) as connection:
        integrity = [
            row[0]
            for row in connection.execute("PRAGMA integrity_check")
        ]

        if integrity != ["ok"]:
            raise RuntimeError(f"Integrity check failed: {integrity}")

        foreign_key_errors = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        if foreign_key_errors:
            raise RuntimeError("Foreign key check failed.")

        counts = {}

        for table in ("alerts", "audit_log", "incident_cases"):
            counts[table] = connection.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone()[0]

        return counts


def main() -> None:
    if not DATABASE_PATH.is_file():
        raise FileNotFoundError(f"Database not found: {DATABASE_PATH}")

    if not ASSETS_PATH.is_file():
        raise FileNotFoundError(f"Inventory not found: {ASSETS_PATH}")

    assets_bytes = ASSETS_PATH.read_bytes()
    assets = json.loads(assets_bytes.decode("utf-8"))

    if not isinstance(assets, list):
        raise ValueError("Asset inventory must be a JSON array.")

    if not all(isinstance(asset, dict) for asset in assets):
        raise ValueError("Each asset inventory entry must be an object.")

    started_at = datetime.now(UTC)
    package_id = (
        started_at.strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )

    package_dir = OUTPUT_ROOT / package_id
    package_dir.mkdir(parents=True, exist_ok=False)

    try:
        database_copy = package_dir / "database.db"
        assets_copy = package_dir / "assets.json"
        manifest_path = package_dir / "manifest.json"

        assets_copy.write_bytes(assets_bytes)

        with closing(
            sqlite3.connect(
                f"{DATABASE_PATH.resolve().as_uri()}?mode=ro",
                uri=True,
                timeout=30,
            )
        ) as source:
            with closing(sqlite3.connect(database_copy)) as destination:
                source.backup(destination)

        counts = validate_database(database_copy)

        if ASSETS_PATH.read_bytes() != assets_bytes:
            raise RuntimeError(
                "Inventory changed during packaging. "
                "Retry when inventory is stable."
            )

        git_commit = git_output("rev-parse", "HEAD")
        git_status = git_output("status", "--porcelain")
        completed_at = datetime.now(UTC)

        files = [
            {
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in (database_copy, assets_copy)
        ]

        manifest = {
            "format_version": 1,
            "status": "created",
            "package_id": package_id,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "source_database": str(
                DATABASE_PATH.relative_to(PROJECT_ROOT)
            ),
            "source_inventory": str(
                ASSETS_PATH.relative_to(PROJECT_ROOT)
            ),
            "git_commit": git_commit,
            "git_working_tree_dirty": (
                None if git_status is None else bool(git_status)
            ),
            "database_integrity_check": "ok",
            "database_foreign_key_check": "ok",
            "database_table_counts": counts,
            "asset_count": len(assets),
            "files": files,
            "configuration_names": CONFIGURATION_NAMES,
            "sensitive_configuration_names": (
                SENSITIVE_CONFIGURATION_NAMES
            ),
            "configuration_values_included": False,
            "application_code_included": False,
            "external_audit_file_included": False,
            "encrypted": False,
            "database_and_inventory_atomic_snapshot": False,
            "recovery_verified": False,
        }

        manifest_path.write_text(
            json.dumps(manifest, indent=2),
            encoding="utf-8",
        )

    except Exception as error:
        try:
            shutil.rmtree(package_dir)
        except Exception as cleanup_error:
            error.add_note(
                "Failed to remove incomplete recovery package "
                f"at {package_dir}: {cleanup_error}"
            )

        raise

    print(json.dumps(manifest, indent=2))
    print(
        "\nPackage directory:",
        package_dir.relative_to(PROJECT_ROOT),
    )

if __name__ == "__main__":
    main()