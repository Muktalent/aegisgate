"""Reader for Zeek's native tab-separated (ASCII) log format.

A Zeek ASCII log starts with header lines (``#separator``, ``#set_separator``,
``#empty_field``, ``#unset_field``, ``#path``, ``#fields``, ``#types``) and is
followed by one tab-separated record per line. Each record is turned into the
same dictionary that Zeek's JSON writer produces (``id.orig_h``, ``ts`` as
epoch seconds, ``_path``), so both formats go through the same adapter.

Values typed ``time``, ``interval``, ``double``, ``count``, ``int`` and
``port`` become numbers, ``bool`` becomes true/false, ``set``/``vector``
become lists. Unset (``-``) fields are left out; ``(empty)`` gives an empty
string or list. Several logs may be concatenated in one file: each new header
block replaces the previous one.
"""
from __future__ import annotations

from typing import Any

NUMERIC_INT = {"count", "int", "port"}
NUMERIC_FLOAT = {"time", "interval", "double"}


def looks_like_zeek_tsv(text: str) -> bool:
    head = text.lstrip()[:200]
    return head.startswith("#separator") or head.startswith("#fields")


def _unescape_separator(value: str) -> str:
    value = value.strip()
    if value.startswith("\\x"):
        try:
            return bytes.fromhex(value[2:]).decode("ascii")
        except ValueError:
            return "\t"
    return value or "\t"


def _convert(raw: str, kind: str, set_separator: str, empty: str) -> Any:
    if kind.startswith(("set[", "vector[")):
        inner = kind[kind.index("[") + 1:-1]
        if raw == empty:
            return []
        return [_convert(part, inner, set_separator, empty) for part in raw.split(set_separator)]
    if raw == empty:
        return ""
    if kind in NUMERIC_INT:
        return int(raw)
    if kind in NUMERIC_FLOAT:
        return float(raw)
    if kind == "bool":
        if raw not in ("T", "F"):
            raise ValueError(f"invalid bool {raw!r}")
        return raw == "T"
    return raw


def parse_zeek_tsv(text: str, max_record_bytes: int) -> tuple[list[tuple[int, dict[str, Any]]], list[dict[str, Any]]]:
    """Return ([(line, record)], [errors]) like the JSON reader. Never raises."""
    separator, set_separator, empty, unset = "\t", ",", "(empty)", "-"
    path: str | None = None
    fields: list[str] | None = None
    types: list[str] | None = None
    records: list[tuple[int, dict[str, Any]]] = []
    errors: list[dict[str, Any]] = []

    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if line.startswith("#"):
            name, _, value = line[1:].partition(separator if not line.startswith("#separator") else " ")
            if name == "separator":
                separator = _unescape_separator(value)
            elif name == "set_separator":
                set_separator = value
            elif name == "empty_field":
                empty = value
            elif name == "unset_field":
                unset = value
            elif name == "path":
                path = value
            elif name == "fields":
                fields, types = value.split(separator), None
            elif name == "types":
                types = value.split(separator)
            continue                                        # #open / #close and unknown headers
        if fields is None:
            errors.append({"line": number, "reason": "Record before the #fields header."})
            continue
        if len(line.encode("utf-8")) > max_record_bytes:
            errors.append({"line": number, "reason": "Record is larger than 64 KB."})
            continue
        values = line.split(separator)
        if len(values) != len(fields):
            errors.append({"line": number,
                           "reason": f"Expected {len(fields)} fields, found {len(values)}."})
            continue
        record: dict[str, Any] = {}
        try:
            for index, (field, raw) in enumerate(zip(fields, values)):
                if raw == unset:
                    continue
                kind = types[index] if types and index < len(types) else "string"
                record[field] = _convert(raw, kind, set_separator, empty)
        except ValueError:
            errors.append({"line": number, "reason": f"Field {field!r} has an invalid value."})
            continue
        if path:
            record["_path"] = path
        records.append((number, record))

    if fields is None and not errors:
        errors.append({"line": 1, "reason": "The Zeek log has no #fields header."})
    return records, errors
