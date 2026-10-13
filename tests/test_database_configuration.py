import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
DEFAULT_DATABASE_PATH = BACKEND_DIR / "app" / "aegisgate.db"

IMPORT_SCRIPT = """
import json
from app.database import DATABASE_PATH, engine

try:
    print(json.dumps({
        "database_path": str(DATABASE_PATH.resolve()),
        "engine_database_path": str(
            __import__("pathlib").Path(
                engine.url.database
            ).resolve()
        ),
    }))
finally:
    engine.dispose()
"""


def import_database_configuration(
    configured_path: str | None,
    working_directory: Path,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()

    if configured_path is None:
        environment.pop("AEGISGATE_DATABASE_PATH", None)
    else:
        environment["AEGISGATE_DATABASE_PATH"] = configured_path

    environment["PYTHONPATH"] = str(BACKEND_DIR)

    return subprocess.run(
        [sys.executable, "-c", IMPORT_SCRIPT],
        cwd=working_directory,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


@pytest.mark.parametrize(
    "configuration",
    [
        "default",
        "absolute",
        "relative",
        "empty",
        "missing",
    ],
)
def test_database_path_configuration(
    tmp_path,
    configuration,
) -> None:
    existing_database = tmp_path / "recovered.db"

    connection = sqlite3.connect(existing_database)
    try:
        connection.execute(
            "CREATE TABLE verification_marker (id INTEGER PRIMARY KEY)"
        )
        connection.commit()
    finally:
        connection.close()

    missing_database = tmp_path / "does_not_exist.db"

    if configuration == "default":
        configured_path = None
        expected_path = DEFAULT_DATABASE_PATH.resolve()
    elif configuration == "absolute":
        configured_path = str(existing_database.resolve())
        expected_path = existing_database.resolve()
    elif configuration == "relative":
        configured_path = os.path.relpath(
            existing_database,
            PROJECT_ROOT,
        )
        expected_path = existing_database.resolve()
    elif configuration == "empty":
        configured_path = "   "
        expected_path = None
    else:
        configured_path = str(missing_database)
        expected_path = None

    result = import_database_configuration(
        configured_path,
        working_directory=tmp_path,
    )

    if configuration == "empty":
        assert result.returncode != 0
        assert "ValueError" in result.stderr
        assert (
            "AEGISGATE_DATABASE_PATH must not be empty."
            in result.stderr
        )
        return

    if configuration == "missing":
        assert result.returncode != 0
        assert "FileNotFoundError" in result.stderr
        assert "Configured database does not exist:" in result.stderr
        assert not missing_database.exists()
        return

    assert result.returncode == 0, result.stderr

    payload = json.loads(result.stdout)

    assert Path(payload["database_path"]) == expected_path
    assert Path(payload["engine_database_path"]) == expected_path