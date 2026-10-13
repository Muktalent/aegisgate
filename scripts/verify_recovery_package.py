import argparse
import hashlib
import json
import shutil
import sqlite3
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
OUTPUT_ROOT = PROJECT_ROOT / "backups" / "package_verifications"

EXPECTED_FILES = {"database.db", "assets.json"}
EXPECTED_TABLES = ("alerts", "audit_log", "incident_cases")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def connect_read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(
        f"{path.resolve().as_uri()}?mode=ro",
        uri=True,
        timeout=30,
    )


def database_counts(path: Path) -> dict[str, int]:
    with closing(connect_read_only(path)) as connection:
        integrity = [
            row[0]
            for row in connection.execute("PRAGMA integrity_check")
        ]
        require(integrity == ["ok"], "Database integrity check failed.")

        foreign_key_errors = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        require(
            not foreign_key_errors,
            "Database foreign key check failed.",
        )

        return {
            table: connection.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone()[0]
            for table in EXPECTED_TABLES
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify and recover a database-and-inventory package."
    )
    parser.add_argument("--package", required=True, type=Path)
    args = parser.parse_args()

    package_dir = args.package.expanduser().resolve()
    manifest_path = package_dir / "manifest.json"

    require(package_dir.is_dir(), "Package directory does not exist.")
    require(manifest_path.is_file(), "Package manifest does not exist.")

    manifest_hash_before = sha256_file(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    require(isinstance(manifest, dict), "Manifest must be an object.")
    require(manifest.get("format_version") == 1, "Unsupported format.")
    require(manifest.get("status") == "created", "Package is incomplete.")

    entries = manifest.get("files")
    require(isinstance(entries, list), "Manifest files must be a list.")
    require(len(entries) == 2, "Expected exactly two packaged files.")
    require(
        all(isinstance(entry, dict) for entry in entries),
        "Invalid manifest file entry.",
    )

    names = [entry.get("name") for entry in entries]
    require(
        all(isinstance(name, str) for name in names),
        "Invalid packaged filename.",
    )
    require(
        set(names) == EXPECTED_FILES,
        "Unexpected or duplicate packaged filenames.",
    )

    expected_counts = manifest.get("database_table_counts")
    require(
        isinstance(expected_counts, dict),
        "Database counts are missing.",
    )
    require(
        set(expected_counts) == set(EXPECTED_TABLES),
        "Unexpected database count entries.",
    )

    source_hashes = {}

    for entry in entries:
        name = entry["name"]
        path = package_dir / name

        require(path.is_file(), f"Missing packaged file: {name}")
        require(not path.is_symlink(), f"Symlink is not allowed: {name}")
        require(
            path.stat().st_size == entry.get("size_bytes"),
            f"File size does not match: {name}",
        )

        digest = sha256_file(path)
        require(
            digest == entry.get("sha256"),
            f"File hash does not match: {name}",
        )
        source_hashes[name] = digest

    require(
        database_counts(package_dir / "database.db") == expected_counts,
        "Packaged database counts do not match the manifest.",
    )

    assets = json.loads(
        (package_dir / "assets.json").read_text(encoding="utf-8")
    )
    require(isinstance(assets, list), "Inventory must be an array.")
    require(
        all(isinstance(asset, dict) for asset in assets),
        "Inventory entries must be objects.",
    )
    require(
        len(assets) == manifest.get("asset_count"),
        "Asset count does not match the manifest.",
    )

    started_at = datetime.now(UTC)
    verification_id = (
        started_at.strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )

    output_dir = OUTPUT_ROOT / verification_id
    output_dir.mkdir(parents=True, exist_ok=False)

    recovered_database = output_dir / "database.db"
    recovered_assets = output_dir / "assets.json"

    with closing(
        connect_read_only(package_dir / "database.db")
    ) as source:
        with closing(sqlite3.connect(recovered_database)) as destination:
            source.backup(destination)

    shutil.copyfile(package_dir / "assets.json", recovered_assets)

    recovered_counts = database_counts(recovered_database)
    require(
        recovered_counts == expected_counts,
        "Recovered database counts do not match.",
    )
    require(
        sha256_file(recovered_assets) == source_hashes["assets.json"],
        "Recovered inventory does not match the package.",
    )

    with closing(
        connect_read_only(package_dir / "database.db")
    ) as source:
        with closing(connect_read_only(recovered_database)) as recovered:
            source_digest = hashlib.sha256()
            recovered_digest = hashlib.sha256()

            for statement in source.iterdump():
                source_digest.update(statement.encode("utf-8"))
                source_digest.update(b"\n")

            for statement in recovered.iterdump():
                recovered_digest.update(statement.encode("utf-8"))
                recovered_digest.update(b"\n")

            require(
                source_digest.digest() == recovered_digest.digest(),
                "Recovered logical database content does not match.",
            )

    sys.path.insert(0, str(BACKEND_DIR))
    from asset_correlation import find_asset_by_ip, load_assets

    loaded_assets = load_assets(recovered_assets)
    require(
        loaded_assets == assets,
        "Application inventory loader returned different content.",
    )

    checked_ips = set()

    for asset in assets:
        ip_address = asset.get("ip_address")
        require(
            isinstance(ip_address, str) and bool(ip_address.strip()),
            "Asset has a missing or invalid IP address.",
        )
        require(
            ip_address not in checked_ips,
            "Inventory has duplicate IP addresses.",
        )
        checked_ips.add(ip_address)

        require(
            find_asset_by_ip(
                ip_address,
                assets_path=recovered_assets,
            ) == asset,
            "Recovered asset lookup failed.",
        )

    for name, expected_hash in source_hashes.items():
        require(
            sha256_file(package_dir / name) == expected_hash,
            f"Packaged source changed during verification: {name}",
        )

    require(
        sha256_file(manifest_path) == manifest_hash_before,
        "Manifest changed during verification.",
    )

    report = {
        "status": "verified",
        "package_id": manifest["package_id"],
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "package_file_hashes_match": True,
        "database_integrity_check": "ok",
        "database_foreign_key_check": "ok",
        "recovered_table_counts": recovered_counts,
        "database_logical_content_matches": True,
        "recovered_asset_count": len(loaded_assets),
        "inventory_content_matches": True,
        "asset_ip_lookups_verified": len(checked_ips),
        "package_sources_unchanged": True,
        "live_database_selected": False,
        "api_verification_performed": False,
        "full_application_recovery_verified": False,
    }

    (output_dir / "verification.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))

    try:
        display_directory = output_dir.relative_to(PROJECT_ROOT)
    except ValueError:
        display_directory = output_dir.resolve()

    print(
        "\nVerification directory:",
        display_directory,
    )


if __name__ == "__main__":
    main()