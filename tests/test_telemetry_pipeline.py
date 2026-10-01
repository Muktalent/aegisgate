import json
import sys
from pathlib import Path


sys.path.append(
    str(Path(__file__).resolve().parents[1] / "backend")
)


from telemetry_pipeline import process_network_event


ROOT = Path(__file__).resolve().parents[1]
TELEMETRY = ROOT / "data" / "telemetry"


def load_event(filename: str) -> dict:
    return json.loads(
        (TELEMETRY / filename).read_text(
            encoding="utf-8"
        )
    )


def test_suricata_c2_is_denied() -> None:
    result = process_network_event(
        load_event("suricata_eve_sample.json")
    )

    assert result["status"] == "processed"
    assert result["telemetry"]["source"] == "suricata"
    assert result["connection_event"]["user_id"] == (
        "finance.user@aegis-demo.local"
    )
    assert result["risk_assessment"]["score"] == 100
    assert result["access_decision"]["action"] == "deny"


def test_zeek_dns_c2_is_denied() -> None:
    result = process_network_event(
        load_event("zeek_dns_sample.json")
    )

    assert result["status"] == "processed"
    assert result["telemetry"]["source"] == "zeek"
    assert result["telemetry"]["event_type"] == "dns"
    assert result["telemetry"]["indicator"] == (
        "malware-c2.example.test"
    )
    assert result["risk_assessment"]["score"] == 100
    assert result["access_decision"]["action"] == "deny"


def test_zeek_notice_is_denied() -> None:
    result = process_network_event(
        load_event("zeek_notice_sample.json")
    )

    assert result["status"] == "processed"
    assert result["telemetry"]["event_type"] == "notice"
    assert result["connection_event"]["user_id"] == (
        "analyst.one@aegis-demo.local"
    )
    assert result["risk_assessment"]["score"] == 100
    assert result["access_decision"]["action"] == "deny"


def test_unknown_asset_requires_manual_review() -> None:
    result = process_network_event(
        load_event("suricata_unknown_asset_sample.json")
    )

    assert result["status"] == "unresolved_asset"
    assert result["access_decision"]["action"] == "manual_review"
    assert result["access_decision"]["requires_mfa"] is False
    assert result["access_decision"]["requires_analyst_review"] is True
    assert (
        result["error"]
        == "No asset inventory record found for 10.10.10.99."
    )