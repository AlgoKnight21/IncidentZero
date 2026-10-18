"""Parsing, validation and normalisation of raw JSON events.

Rules:
* Missing optional fields stay missing (never invented). Warnings are recorded instead.
* Timestamps must be ISO-8601 with an explicit offset or 'Z'; naive timestamps are rejected
  (we refuse to guess a timezone). All timestamps are normalised to UTC, second precision.
* Exact duplicate event_ids within one batch are collapsed (first wins) and reported.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from pydantic import ValidationError

from app.models.schemas import EVENT_TYPES, NormalizedEvent, RejectedRecord

REQUIRED = ("event_id", "timestamp", "event_type", "source", "source_record_id")
INT_FIELDS = ("process_id", "parent_process_id", "destination_port")
IP_FIELDS = ("source_ip", "destination_ip")
STR_FIELDS = ("host_id", "actor_id", "file_path", "file_hash", "authentication_result", "raw_summary")
MAX_FIELD_LEN = 2048


def parse_timestamp(value: Any) -> tuple[str, int]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"unparseable timestamp {value!r}") from exc
    if dt.tzinfo is None:
        raise ValueError(f"timestamp {value!r} has no timezone; refusing to assume one")
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), int(dt.timestamp())


def normalize_record(raw: Any) -> tuple[NormalizedEvent | None, list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(raw, dict):
        return None, ["record is not a JSON object"]
    if "__parse_error__" in raw:
        return None, [f"invalid JSON: {raw['__parse_error__']}"]
    for f in REQUIRED:
        if raw.get(f) in (None, ""):
            errors.append(f"missing required field '{f}'")
    if errors:
        return None, errors
    if raw["event_type"] not in EVENT_TYPES:
        errors.append(f"unknown event_type {raw['event_type']!r}")
    try:
        ts, epoch = parse_timestamp(raw["timestamp"])
    except ValueError as exc:
        errors.append(str(exc))
        ts, epoch = "", 0
    out: dict[str, Any] = {
        "event_id": str(raw["event_id"]), "timestamp": ts, "ts_epoch": epoch,
        "timestamp_original": str(raw["timestamp"]), "event_type": raw["event_type"],
        "source": str(raw["source"]), "source_record_id": str(raw["source_record_id"]),
    }
    for f in INT_FIELDS:
        v = raw.get(f)
        if v is None:
            continue
        if isinstance(v, bool) or not isinstance(v, (int, str)):
            errors.append(f"{f} must be an integer")
            continue
        try:
            iv = int(v)
        except ValueError:
            errors.append(f"{f} must be an integer, got {v!r}")
            continue
        if iv < 0 or (f == "destination_port" and iv > 65535):
            errors.append(f"{f} out of range: {iv}")
            continue
        out[f] = iv
    for f in IP_FIELDS:
        v = raw.get(f)
        if v is None:
            continue
        try:
            out[f] = str(ipaddress.ip_address(str(v)))
        except ValueError:
            errors.append(f"{f} is not a valid IP address: {v!r}")
    for f in STR_FIELDS:
        v = raw.get(f)
        if v is None:
            continue
        if not isinstance(v, str):
            errors.append(f"{f} must be a string")
            continue
        if len(v) > MAX_FIELD_LEN:
            errors.append(f"{f} exceeds {MAX_FIELD_LEN} characters")
            continue
        out[f] = v
    rf = raw.get("raw_fields", {})
    if rf is None:
        rf = {}
    if not isinstance(rf, dict):
        errors.append("raw_fields must be an object")
        rf = {}
    out["raw_fields"] = rf
    et = raw.get("event_type")
    if not raw.get("host_id") and et not in ("change_record",):
        warnings.append("host_id missing")
    if et == "authentication":
        if not raw.get("actor_id"):
            warnings.append("authentication without actor_id")
        if not raw.get("authentication_result"):
            warnings.append("authentication without authentication_result")
        if not raw.get("source_ip"):
            warnings.append("authentication without source_ip; origin host cannot be derived")
    if et == "process_creation" and raw.get("process_id") is None:
        warnings.append("process_creation without process_id")
    if et == "network_connection" and not raw.get("destination_ip"):
        warnings.append("network_connection without destination_ip")
    if et == "file_access" and not raw.get("file_path"):
        warnings.append("file_access without file_path")
    if errors:
        return None, errors
    out["warnings"] = warnings
    try:
        return NormalizedEvent(**out), []
    except ValidationError as exc:
        return None, [f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()]


def normalize_batch(records: Iterable[Any]) -> tuple[list[NormalizedEvent], list[str], list[RejectedRecord], list[str]]:
    """Returns (accepted, duplicate_ids, rejected, warnings)."""
    accepted: list[NormalizedEvent] = []
    seen: dict[str, NormalizedEvent] = {}
    duplicates: list[str] = []
    rejected: list[RejectedRecord] = []
    warnings: list[str] = []
    for i, raw in enumerate(records, start=1):
        ev, errs = normalize_record(raw)
        if ev is None:
            eid = raw.get("event_id") if isinstance(raw, dict) else None
            rejected.append(RejectedRecord(line=i, event_id=str(eid) if eid is not None else None, errors=errs))
            continue
        if ev.event_id in seen:
            prev = seen[ev.event_id]
            if prev.model_dump() != ev.model_dump():
                warnings.append(f"{ev.event_id}: conflicting duplicate record ignored (first record kept)")
            duplicates.append(ev.event_id)
            continue
        seen[ev.event_id] = ev
        accepted.append(ev)
        warnings.extend(f"{ev.event_id}: {w}" for w in ev.warnings)
    return accepted, duplicates, rejected, warnings


def read_jsonl(text: str) -> list[Any]:
    out: list[Any] = []
    for n, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as exc:
            out.append({"__parse_error__": f"line {n}: {exc.msg}"})
    return out
