import argparse
import hashlib
import json
import os
import sqlite3
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
OUTPUT_ROOT = PROJECT_ROOT / "backups" / "api_verifications"
NORMAL_DATABASE = BACKEND_DIR / "app" / "aegisgate.db"


def file_digest(path: Path) -> str:
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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify API reads against a recovered database."
    )
    parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="Path to the recovered snapshot, not the live database.",
    )
    args = parser.parse_args()

    source_path = args.database.expanduser().resolve()

    require(source_path.is_file(), "Recovered database does not exist.")
    require(
        source_path != NORMAL_DATABASE.resolve(),
        "Do not use the live database for this verification.",
    )

    started_at = datetime.now(UTC)
    verification_id = (
        started_at.strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )

    output_dir = OUTPUT_ROOT / verification_id
    output_dir.mkdir(parents=True, exist_ok=False)

    copied_database = output_dir / "api_test.db"
    report_path = output_dir / "verification.json"

    source_hash_before = file_digest(source_path)

    with closing(connect_read_only(source_path)) as source:
        with closing(sqlite3.connect(copied_database)) as destination:
            source.backup(destination)

    with closing(connect_read_only(copied_database)) as connection:
        integrity = [
            row[0]
            for row in connection.execute("PRAGMA integrity_check")
        ]
        require(integrity == ["ok"], "Copied database is not valid.")

        expected_event_ids = {
            row[0]
            for row in connection.execute(
                "SELECT event_id FROM alerts"
            )
        }

        expected_cases = {
            row[0]: row[1]
            for row in connection.execute(
                """
                SELECT case_id, alert_event_id
                FROM incident_cases
                """
            )
        }

        audit_count = connection.execute(
            "SELECT COUNT(*) FROM audit_log"
        ).fetchone()[0]

    previous_path = os.environ.get("AEGISGATE_DATABASE_PATH")
    os.environ["AEGISGATE_DATABASE_PATH"] = str(copied_database)
    sys.path.insert(0, str(BACKEND_DIR))

    api = None

    try:
        from fastapi.testclient import TestClient
        import app.main as api
        from app.database import DATABASE_PATH
        from security import create_access_token

        require(
            DATABASE_PATH.resolve() == copied_database.resolve(),
            "Application did not select the isolated database.",
        )

        token = create_access_token(
            username="restore-verification",
            role="soc_analyst",
        )
        headers = {"Authorization": f"Bearer {token}"}

        with TestClient(api.app) as client:
            health_response = client.get("/health")
            require(
                health_response.status_code == 200,
                f"Health returned HTTP {health_response.status_code}.",
            )
            require(
                health_response.json().get("status") == "ok",
                "Health response did not report status ok.",
            )

            events_response = client.get(
                "/v1/events",
                headers=headers,
            )
            require(
                events_response.status_code == 200,
                f"Events returned HTTP {events_response.status_code}.",
            )

            events = events_response.json()
            require(isinstance(events, list), "Events is not a list.")

            actual_event_ids = {
                event["event_id"]
                for event in events
            }

            require(
                len(events) == len(expected_event_ids),
                "API event count does not match the snapshot.",
            )
            require(
                actual_event_ids == expected_event_ids,
                "API event identifiers do not match the snapshot.",
            )

            cases_response = client.get(
                "/v1/cases",
                headers=headers,
            )
            require(
                cases_response.status_code == 200,
                f"Cases returned HTTP {cases_response.status_code}.",
            )

            cases = cases_response.json()
            require(isinstance(cases, list), "Cases is not a list.")

            actual_cases = {
                case["case_id"]: case["alert_event_id"]
                for case in cases
            }

            require(
                len(cases) == len(expected_cases),
                "API case count does not match the snapshot.",
            )
            require(
                actual_cases == expected_cases,
                "API case identifiers or alert links do not match.",
            )

        source_hash_after = file_digest(source_path)

        require(
            source_hash_before == source_hash_after,
            "Recovered source file changed during verification.",
        )

        completed_at = datetime.now(UTC)

        report = {
            "status": "verified",
            "verification_mode": "in_process_testclient",
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_seconds": (
                completed_at - started_at
            ).total_seconds(),
            "health_http_status": health_response.status_code,
            "events_http_status": events_response.status_code,
            "cases_http_status": cases_response.status_code,
            "expected_event_count": len(expected_event_ids),
            "returned_event_count": len(events),
            "expected_case_count": len(expected_cases),
            "returned_case_count": len(cases),
            "snapshot_audit_count": audit_count,
            "event_identifiers_match": True,
            "case_identifiers_and_alert_links_match": True,
            "recovered_source_unchanged": True,
            "isolated_database_selected": True,
            "live_database_selected": False,
        }

        report_path.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

        print(json.dumps(report, indent=2))
        print(
            "\nVerification directory:",
            output_dir.relative_to(PROJECT_ROOT),
        )

    finally:
        if api is not None:
            api.engine.dispose()

        if previous_path is None:
            os.environ.pop("AEGISGATE_DATABASE_PATH", None)
        else:
            os.environ["AEGISGATE_DATABASE_PATH"] = previous_path


if __name__ == "__main__":
    main()