"""Scenario discovery and ingestion orchestration (engine-visible data only)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.config import Settings, assert_engine_readable, get_settings
from app.graph.client import GraphClient
from app.graph.schema import ensure_indexes
from app.graph.writer import Stats, write_events, write_inventory
from app.ingestion.normalize import normalize_batch, read_jsonl
from app.models.schemas import IngestResult

SCENARIO_ID_RE = re.compile(r"^[a-z0-9_]{1,64}$")


class ScenarioNotFound(LookupError):
    pass


def _scenario_dir(settings: Settings, scenario_id: str) -> Path:
    if not SCENARIO_ID_RE.match(scenario_id):
        raise ScenarioNotFound(f"invalid scenario id {scenario_id!r}")
    root = assert_engine_readable(settings.scenario_root)
    d = (root / scenario_id).resolve()
    if d.parent != root or not d.is_dir():
        raise ScenarioNotFound(f"scenario {scenario_id!r} not found")
    return assert_engine_readable(d)


def list_scenarios(settings: Settings | None = None) -> list[dict[str, Any]]:
    settings = settings or get_settings()
    root = assert_engine_readable(settings.scenario_root)
    out = []
    if not root.is_dir():
        return out
    for d in sorted(root.iterdir()):
        meta = d / "scenario.json"
        if d.is_dir() and meta.is_file() and SCENARIO_ID_RE.match(d.name):
            out.append(json.loads(meta.read_text()))
    return out


def read_scenario(scenario_id: str, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    d = _scenario_dir(settings, scenario_id)
    return {
        "meta": json.loads((d / "scenario.json").read_text()),
        "records": read_jsonl((d / "events.jsonl").read_text()),
        "hosts": json.loads((d / "hosts.json").read_text()) if (d / "hosts.json").exists() else [],
        "identities": json.loads((d / "identities.json").read_text()) if (d / "identities.json").exists() else [],
        "manifest": json.loads((d / "manifest.json").read_text()) if (d / "manifest.json").exists() else {},
    }


def ingest(client: GraphClient, scenario_id: str, records: list[Any], hosts: list[dict], identities: list[dict],
           settings: Settings | None = None) -> IngestResult:
    settings = settings or get_settings()
    if len(records) > settings.max_ingest_records:
        raise ValueError(f"too many records ({len(records)} > {settings.max_ingest_records})")
    accepted, dups, rejected, warnings = normalize_batch(records)
    ensure_indexes(client, scenario_id)
    stats = Stats()
    write_inventory(client, scenario_id, hosts, identities, stats)
    if accepted:
        write_events(client, scenario_id, accepted, stats)
    return IngestResult(scenario_id=scenario_id, graph=client.graph_name(scenario_id), received=len(records),
                        accepted=len(accepted), duplicates_in_batch=dups, rejected=rejected, warnings=warnings,
                        nodes_created=stats.nodes_created, relationships_created=stats.relationships_created,
                        properties_set=stats.properties_set)


def load_scenario(client: GraphClient, scenario_id: str, reset: bool = False,
                  settings: Settings | None = None) -> IngestResult:
    data = read_scenario(scenario_id, settings)
    if reset:
        client.delete_graph(scenario_id)
    return ingest(client, scenario_id, data["records"], data["hosts"], data["identities"], settings)
