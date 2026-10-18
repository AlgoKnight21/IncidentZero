"""Typed models for events, ingestion results and investigation output."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

EventType = Literal[
    "process_creation", "network_connection", "authentication", "file_access",
    "edr_alert", "telemetry_status", "change_record", "dns_resolution",
]
EVENT_TYPES: set[str] = set(EventType.__args__)  # type: ignore[attr-defined]


class NormalizedEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=128)
    timestamp: str  # normalised ISO-8601 UTC "YYYY-MM-DDTHH:MM:SSZ"
    ts_epoch: int
    timestamp_original: str
    event_type: str
    source: str
    source_record_id: str
    host_id: str | None = None
    actor_id: str | None = None
    process_id: int | None = None
    parent_process_id: int | None = None
    file_path: str | None = None
    file_hash: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    authentication_result: Literal["success", "failure"] | None = None
    raw_summary: str = ""
    raw_fields: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class RejectedRecord(BaseModel):
    line: int
    event_id: str | None
    errors: list[str]


class IngestResult(BaseModel):
    scenario_id: str
    graph: str
    received: int
    accepted: int
    duplicates_in_batch: list[str]
    rejected: list[RejectedRecord]
    warnings: list[str]
    nodes_created: int
    relationships_created: int
    properties_set: int


class InvestigationRequest(BaseModel):
    scenario_id: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    question: str = Field(default="", max_length=2000)
    seed_event_id: str | None = Field(default=None, max_length=128)
    window_minutes: int = Field(default=60, ge=1, le=24 * 60)


class EventIngestRequest(BaseModel):
    scenario_id: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    events: list[dict[str, Any]] = Field(max_length=5000)
    hosts: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    identities: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
