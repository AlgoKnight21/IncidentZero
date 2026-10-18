"""Graph schema: range indexes, created through the falkordb-py index helpers.

Index creation is repeatable: an "already indexed" error from FalkorDB is treated as success.
"""
from __future__ import annotations

from app.graph.client import GraphClient, GraphQueryError, GraphUnavailableError

NODE_INDEXES: list[tuple[str, str]] = [
    ("Event", "event_id"),
    ("Event", "event_type"),
    ("Event", "ts_epoch"),
    ("Event", "source"),
    ("Host", "host_id"),
    ("Identity", "account_id"),
    ("Process", "process_key"),
    ("File", "path"),
    ("NetworkEndpoint", "ip"),
    ("Investigation", "investigation_id"),
    ("Hypothesis", "hypothesis_id"),
]


def ensure_indexes(client: GraphClient, scenario_id: str) -> dict[str, int]:
    g = client.graph(scenario_id)
    created = 0
    existing = 0
    for label, prop in NODE_INDEXES:
        try:
            res = client.guarded(g.create_node_range_index, label, prop)
            created += res.indices_created
        except GraphUnavailableError:
            raise
        except Exception as exc:  # FalkorDB raises ResponseError when the attribute is already indexed
            msg = str(exc).lower()
            if "already indexed" in msg or "already exists" in msg:
                existing += 1
                continue
            raise GraphQueryError(f"index creation failed for :{label}({prop}): {exc}") from exc
    return {"created": created, "already_present": existing}


def list_indexes(client: GraphClient, scenario_id: str) -> list[dict]:
    rows = client.rows(scenario_id, "CALL db.indexes() YIELD label, properties, types, entitytype "
                                    "RETURN label, properties, types, entitytype")
    return rows
