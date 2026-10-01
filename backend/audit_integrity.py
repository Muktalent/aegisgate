import hashlib
import hmac
import json
from pathlib import Path

from config import AUDIT_HMAC_KEY


GENESIS_HASH = "GENESIS"
HASH_ALGORITHM = "HMAC-SHA-256"


def canonical_json(record: dict) -> bytes:
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def calculate_record_hash(record: dict) -> str:
    record_to_sign = {
        key: value
        for key, value in record.items()
        if key != "record_hash"
    }

    return hmac.new(
        AUDIT_HMAC_KEY.encode("utf-8"),
        canonical_json(record_to_sign),
        hashlib.sha256,
    ).hexdigest()


def get_last_record_hash(audit_file: Path) -> str:
    if not audit_file.exists():
        return GENESIS_HASH

    last_record = None

    with audit_file.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            last_record = json.loads(line)

    if last_record is None:
        return GENESIS_HASH

    return last_record.get("record_hash", GENESIS_HASH)


def sign_audit_record(record: dict, audit_file: Path) -> dict:
    signed_record = {
        **record,
        "hash_algorithm": HASH_ALGORITHM,
        "previous_hash": get_last_record_hash(audit_file),
    }

    signed_record["record_hash"] = calculate_record_hash(signed_record)

    return signed_record