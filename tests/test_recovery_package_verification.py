import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = (
    PROJECT_ROOT / "scripts" / "verify_recovery_package.py"
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def verifier(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "recovery_package_verifier_for_tests",
        VERIFIER_PATH,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load recovery package verifier.")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    monkeypatch.setattr(
        module,
        "OUTPUT_ROOT",
        tmp_path / "verification_output",
    )

    return module


@pytest.fixture
def synthetic_package(tmp_path):
    package_dir = tmp_path / "synthetic_package"
    package_dir.mkdir()

    database_path = package_dir / "database.db"
    inventory_path = package_dir / "assets.json"

    connection = sqlite3.connect(database_path)

    try:
        connection.executescript(
            """
            CREATE TABLE alerts (
                event_id TEXT PRIMARY KEY
            );

            CREATE TABLE audit_log (
                audit_id INTEGER PRIMARY KEY
            );

            CREATE TABLE incident_cases (
                case_id TEXT PRIMARY KEY,
                alert_event_id TEXT NOT NULL
            );

            INSERT INTO alerts VALUES ('event-test-001');
            INSERT INTO audit_log VALUES (1);
            INSERT INTO incident_cases
            VALUES ('case-test-001', 'event-test-001');
            """
        )
        connection.commit()
    finally:
        connection.close()

    inventory_path.write_text(
        json.dumps(
            [
                {
                    "ip_address": "10.10.10.50",
                    "device_name": "Recovery test asset",
                }
            ]
        ),
        encoding="utf-8",
    )

    manifest = {
        "format_version": 1,
        "status": "created",
        "package_id": "synthetic-test-package",
        "database_table_counts": {
            "alerts": 1,
            "audit_log": 1,
            "incident_cases": 1,
        },
        "asset_count": 1,
        "files": [
            {
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in (database_path, inventory_path)
        ],
    }

    (package_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    return package_dir


@pytest.mark.parametrize(
    "scenario, expected_error",
    [
        ("valid", None),
        ("modified_database", "File hash does not match: database.db"),
        ("modified_inventory", "File hash does not match: assets.json"),
        ("missing_file", "Missing packaged file: assets.json"),
        (
            "unexpected_filename",
            "Unexpected or duplicate packaged filenames.",
        ),
    ],
)
def test_recovery_package_verification(
    verifier,
    synthetic_package,
    monkeypatch,
    scenario,
    expected_error,
):
    package_dir = synthetic_package
    database_path = package_dir / "database.db"
    inventory_path = package_dir / "assets.json"
    manifest_path = package_dir / "manifest.json"

    if scenario == "modified_database":
        database_bytes = bytearray(database_path.read_bytes())
        database_bytes[-1] ^= 1
        database_path.write_bytes(database_bytes)

    elif scenario == "modified_inventory":
        inventory_bytes = inventory_path.read_bytes()
        assert b"10.10.10.50" in inventory_bytes
        inventory_path.write_bytes(
            inventory_bytes.replace(
                b"10.10.10.50",
                b"10.10.10.51",
                1,
            )
        )

    elif scenario == "missing_file":
        inventory_path.unlink()

    elif scenario == "unexpected_filename":
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
        manifest["files"][0]["name"] = "../unexpected.db"
        manifest_path.write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

    source_hashes_before = {
        path.name: sha256_file(path)
        for path in package_dir.iterdir()
        if path.is_file()
    }

    monkeypatch.setattr(
        "sys.argv",
        [
            str(VERIFIER_PATH),
            "--package",
            str(package_dir),
        ],
    )

    if expected_error is not None:
        with pytest.raises(RuntimeError) as error:
            verifier.main()

        assert expected_error in str(error.value)
        assert not verifier.OUTPUT_ROOT.exists()

    else:
        verifier.main()

        report_paths = list(
            verifier.OUTPUT_ROOT.glob("*/verification.json")
        )
        assert len(report_paths) == 1

        report = json.loads(
            report_paths[0].read_text(encoding="utf-8")
        )

        assert report["status"] == "verified"
        assert report["package_id"] == "synthetic-test-package"
        assert report["package_file_hashes_match"] is True
        assert report["database_integrity_check"] == "ok"
        assert report["database_foreign_key_check"] == "ok"
        assert report["database_logical_content_matches"] is True
        assert report["recovered_table_counts"] == {
            "alerts": 1,
            "audit_log": 1,
            "incident_cases": 1,
        }
        assert report["recovered_asset_count"] == 1
        assert report["asset_ip_lookups_verified"] == 1
        assert report["inventory_content_matches"] is True
        assert report["package_sources_unchanged"] is True
        assert report["live_database_selected"] is False
        assert report["api_verification_performed"] is False
        assert report["full_application_recovery_verified"] is False

        recovered_dir = report_paths[0].parent
        assert (recovered_dir / "database.db").is_file()
        assert (recovered_dir / "assets.json").is_file()

    source_hashes_after = {
        path.name: sha256_file(path)
        for path in package_dir.iterdir()
        if path.is_file()
    }

    assert source_hashes_after == source_hashes_before