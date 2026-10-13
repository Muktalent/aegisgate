import hashlib
import importlib.util
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CREATOR_PATH = PROJECT_ROOT / "scripts" / "create_recovery_package.py"
VERIFIER_PATH = PROJECT_ROOT / "scripts" / "verify_recovery_package.py"


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)

    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load script: {path.name}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def creator(tmp_path, monkeypatch):
    module = load_script(
        "recovery_package_creator_for_tests",
        CREATOR_PATH,
    )

    project_root = tmp_path / "project"
    database_path = project_root / "backend" / "app" / "aegisgate.db"
    inventory_path = project_root / "data" / "assets.json"

    database_path.parent.mkdir(parents=True)
    inventory_path.parent.mkdir(parents=True)

    with closing(sqlite3.connect(database_path)) as connection:
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
                alert_event_id TEXT NOT NULL,
                FOREIGN KEY (alert_event_id)
                    REFERENCES alerts(event_id)
            );

            INSERT INTO alerts VALUES ('event-test-001');
            INSERT INTO audit_log VALUES (1);
            INSERT INTO incident_cases
            VALUES ('case-test-001', 'event-test-001');
            """
        )
        connection.commit()

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

    monkeypatch.setattr(module, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(module, "DATABASE_PATH", database_path)
    monkeypatch.setattr(module, "ASSETS_PATH", inventory_path)
    monkeypatch.setattr(
        module,
        "OUTPUT_ROOT",
        project_root / "backups" / "recovery_packages",
    )
    monkeypatch.setattr(
        module,
        "git_output",
        lambda *arguments: None,
    )

    return module

def get_package_directory(creator) -> Path:
    package_directories = list(creator.OUTPUT_ROOT.iterdir())

    assert len(package_directories) == 1
    assert package_directories[0].is_dir()

    return package_directories[0]


def source_hashes(creator) -> dict[str, str]:
    return {
        "database": sha256_file(creator.DATABASE_PATH),
        "inventory": sha256_file(creator.ASSETS_PATH),
    }


def test_creation_produces_valid_manifest_and_preserves_sources(creator):
    hashes_before = source_hashes(creator)

    creator.main()

    package_dir = get_package_directory(creator)
    manifest = json.loads(
        (package_dir / "manifest.json").read_text(encoding="utf-8")
    )

    assert {path.name for path in package_dir.iterdir()} == {
        "database.db",
        "assets.json",
        "manifest.json",
    }

    assert manifest["format_version"] == 1
    assert manifest["status"] == "created"
    assert manifest["package_id"] == package_dir.name
    assert manifest["source_database"] == str(
        Path("backend") / "app" / "aegisgate.db"
    )
    assert manifest["source_inventory"] == str(
        Path("data") / "assets.json"
    )
    assert manifest["database_integrity_check"] == "ok"
    assert manifest["database_foreign_key_check"] == "ok"
    assert manifest["database_table_counts"] == {
        "alerts": 1,
        "audit_log": 1,
        "incident_cases": 1,
    }
    assert manifest["asset_count"] == 1

    assert len(manifest["files"]) == 2
    assert {entry["name"] for entry in manifest["files"]} == {
        "database.db",
        "assets.json",
    }

    for entry in manifest["files"]:
        packaged_file = package_dir / entry["name"]

        assert entry["size_bytes"] == packaged_file.stat().st_size
        assert entry["sha256"] == sha256_file(packaged_file)

    assert (package_dir / "assets.json").read_bytes() == (
        creator.ASSETS_PATH.read_bytes()
    )
    assert creator.validate_database(package_dir / "database.db") == {
        "alerts": 1,
        "audit_log": 1,
        "incident_cases": 1,
    }

    assert manifest["configuration_names"] == creator.CONFIGURATION_NAMES
    assert manifest["sensitive_configuration_names"] == (
        creator.SENSITIVE_CONFIGURATION_NAMES
    )
    assert manifest["configuration_values_included"] is False
    assert manifest["application_code_included"] is False
    assert manifest["external_audit_file_included"] is False
    assert manifest["encrypted"] is False
    assert manifest["database_and_inventory_atomic_snapshot"] is False
    assert manifest["recovery_verified"] is False
    assert manifest["git_commit"] is None
    assert manifest["git_working_tree_dirty"] is None

    assert source_hashes(creator) == hashes_before


@pytest.mark.parametrize(
    "attribute, expected_error",
    [
        ("DATABASE_PATH", "Database not found:"),
        ("ASSETS_PATH", "Inventory not found:"),
    ],
)
def test_creation_rejects_missing_sources(
    creator,
    attribute,
    expected_error,
):
    getattr(creator, attribute).unlink()

    with pytest.raises(FileNotFoundError, match=expected_error):
        creator.main()

    assert not creator.OUTPUT_ROOT.exists()


@pytest.mark.parametrize(
    "inventory_content, expected_exception, expected_error",
    [
        (
            "{invalid-json",
            json.JSONDecodeError,
            None,
        ),
        (
            '{"ip_address": "10.10.10.50"}',
            ValueError,
            "Asset inventory must be a JSON array.",
        ),
        (
            '["invalid-entry"]',
            ValueError,
            "Each asset inventory entry must be an object.",
        ),
    ],
)
def test_creation_rejects_invalid_inventory(
    creator,
    inventory_content,
    expected_exception,
    expected_error,
):
    creator.ASSETS_PATH.write_text(
        inventory_content,
        encoding="utf-8",
    )
    hashes_before = source_hashes(creator)

    with pytest.raises(expected_exception) as error:
        creator.main()

    if expected_error is not None:
        assert expected_error in str(error.value)

    assert not creator.OUTPUT_ROOT.exists()
    assert source_hashes(creator) == hashes_before


def test_created_package_is_accepted_by_verifier(
    creator,
    tmp_path,
    monkeypatch,
):
    hashes_before = source_hashes(creator)

    creator.main()
    package_dir = get_package_directory(creator)

    package_hashes_before = {
        path.name: sha256_file(path)
        for path in package_dir.iterdir()
        if path.is_file()
    }

    verifier = load_script(
        "created_recovery_package_verifier_for_tests",
        VERIFIER_PATH,
    )
    monkeypatch.setattr(
        verifier,
        "OUTPUT_ROOT",
        tmp_path / "verification_output",
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            str(VERIFIER_PATH),
            "--package",
            str(package_dir),
        ],
    )

    verifier.main()

    report_paths = list(
        verifier.OUTPUT_ROOT.glob("*/verification.json")
    )
    assert len(report_paths) == 1

    report = json.loads(
        report_paths[0].read_text(encoding="utf-8")
    )

    assert report["status"] == "verified"
    assert report["package_id"] == package_dir.name
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

    package_hashes_after = {
        path.name: sha256_file(path)
        for path in package_dir.iterdir()
        if path.is_file()
    }

    assert package_hashes_after == package_hashes_before
    assert source_hashes(creator) == hashes_before

def test_creation_rejects_invalid_database(creator):
    creator.DATABASE_PATH.write_bytes(b"Not a SQLite database.")
    hashes_before = source_hashes(creator)

    with pytest.raises(sqlite3.DatabaseError):
        creator.main()

    assert source_hashes(creator) == hashes_before
    assert creator.OUTPUT_ROOT.is_dir()
    assert list(creator.OUTPUT_ROOT.iterdir()) == []


def test_creation_rejects_missing_required_table(creator):
    with closing(
        sqlite3.connect(creator.DATABASE_PATH)
    ) as connection:
        connection.execute("DROP TABLE audit_log")
        connection.commit()

    hashes_before = source_hashes(creator)

    with pytest.raises(
        sqlite3.OperationalError,
        match="no such table: audit_log",
    ):
        creator.main()

    assert source_hashes(creator) == hashes_before
    assert creator.OUTPUT_ROOT.is_dir()
    assert list(creator.OUTPUT_ROOT.iterdir()) == []


def test_creation_rejects_inventory_changed_during_packaging(
    creator,
    monkeypatch,
):
    database_hash_before = sha256_file(creator.DATABASE_PATH)
    original_validate_database = creator.validate_database

    changed_inventory = json.dumps(
        [
            {
                "ip_address": "10.10.10.51",
                "device_name": "Changed recovery test asset",
            }
        ]
    ).encode("utf-8")

    def validate_database_and_change_inventory(path):
        counts = original_validate_database(path)
        creator.ASSETS_PATH.write_bytes(changed_inventory)
        return counts

    monkeypatch.setattr(
        creator,
        "validate_database",
        validate_database_and_change_inventory,
    )

    with pytest.raises(
        RuntimeError,
        match="Inventory changed during packaging",
    ):
        creator.main()

    assert sha256_file(creator.DATABASE_PATH) == database_hash_before
    assert creator.ASSETS_PATH.read_bytes() == changed_inventory
    assert creator.OUTPUT_ROOT.is_dir()
    assert list(creator.OUTPUT_ROOT.iterdir()) == []

def test_creation_removes_partial_package_when_manifest_write_fails(
    creator,
    monkeypatch,
):
    hashes_before = source_hashes(creator)
    original_write_text = Path.write_text

    def fail_manifest_write(path, *args, **kwargs):
        if path.name == "manifest.json":
            raise OSError("Simulated manifest write failure.")

        return original_write_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_manifest_write)

    with pytest.raises(
        OSError,
        match="Simulated manifest write failure",
    ):
        creator.main()

    assert creator.OUTPUT_ROOT.is_dir()
    assert list(creator.OUTPUT_ROOT.iterdir()) == []
    assert source_hashes(creator) == hashes_before


def test_creation_preserves_original_error_when_cleanup_fails(
    creator,
    monkeypatch,
):
    hashes_before = source_hashes(creator)

    def fail_validation(path):
        raise RuntimeError("Simulated database validation failure.")

    def fail_cleanup(path):
        raise PermissionError("Simulated cleanup failure.")

    monkeypatch.setattr(
        creator,
        "validate_database",
        fail_validation,
    )
    monkeypatch.setattr(
        creator.shutil,
        "rmtree",
        fail_cleanup,
    )

    with pytest.raises(
        RuntimeError,
        match="Simulated database validation failure",
    ) as error:
        creator.main()

    notes = getattr(error.value, "__notes__", [])

    assert any(
        "Failed to remove incomplete recovery package" in note
        and "Simulated cleanup failure." in note
        for note in notes
    )

    package_dir = get_package_directory(creator)

    assert not (package_dir / "manifest.json").exists()
    assert source_hashes(creator) == hashes_before