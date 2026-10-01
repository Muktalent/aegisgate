import json
from pathlib import Path
from typing import Any

from telemetry_models import NetworkTelemetryEvent


DEFAULT_ASSETS_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "assets.json"
)


def load_assets(
    assets_path: str | Path = DEFAULT_ASSETS_PATH,
) -> list[dict[str, Any]]:
    with Path(assets_path).open(encoding="utf-8") as handle:
        assets = json.load(handle)

    if not isinstance(assets, list):
        raise ValueError("Asset inventory must be a JSON array.")

    return assets


def find_asset_by_ip(
    source_ip: str,
    assets_path: str | Path = DEFAULT_ASSETS_PATH,
) -> dict[str, Any] | None:
    assets = load_assets(assets_path)

    return next(
        (
            asset
            for asset in assets
            if asset.get("ip_address") == source_ip
        ),
        None,
    )


def correlate_event(
    event: NetworkTelemetryEvent,
    assets_path: str | Path = DEFAULT_ASSETS_PATH,
) -> dict[str, Any]:
    asset = find_asset_by_ip(event.source_ip, assets_path)

    return {
        "asset_found": asset is not None,
        "asset": asset,
        "event": event.model_dump(
            mode="json",
            exclude={"raw_event"},
        ),
    }