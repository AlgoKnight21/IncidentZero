"""Idempotent graph construction.

Every write uses MERGE on a stable key with ON CREATE SET, so reloading the same scenario creates no
duplicate nodes or relationships and does not mutate already-stored evidence.

Relationship classification (stored on every relationship as `classification`):
  observed            the relationship is stated directly by one event field (e.g. Event-[:ON_HOST]->Host)
  derived_from_field  built from an explicit reference field linking two entities (parent_process_id)
  inferred            produced by a documented rule (`derivation`) over several facts, with `evidence` ids
Temporal order is never materialised as a causal edge; ordering is computed from ts_epoch at query time.
"""
from __future__ import annotations

import json
import time
from typing import Any

from app.graph.client import GraphClient
from app.models.schemas import NormalizedEvent

BATCH = 200

EXTRACT_RAW = {  # raw_fields keys promoted to Event properties for querying (values copied verbatim)
    "image": "image", "parent_image": "parent_image", "command_line": "command_line", "signed": "signed",
    "rule": "alert_rule", "severity": "severity", "action": "alert_action", "sensor": "sensor",
    "status": "sensor_status", "change_id": "change_id", "logon_type": "logon_type", "access": "access",
    "protocol": "protocol", "bytes_out": "bytes_out", "approved_by": "approved_by", "reason": "auth_failure_reason",
}

Q_HOSTS = """
UNWIND $rows AS h
MERGE (x:Host {host_id: h.host_id})
ON CREATE SET x.platform = h.platform, x.asset_role = h.asset_role, x.ip = h.ip, x.in_inventory = true,
              x.source = 'asset_inventory'
ON MATCH SET x.in_inventory = true, x.platform = coalesce(x.platform, h.platform),
             x.asset_role = coalesce(x.asset_role, h.asset_role), x.ip = coalesce(x.ip, h.ip)
WITH x, h WHERE h.ip IS NOT NULL
MERGE (n:NetworkEndpoint {ip: h.ip})
MERGE (x)-[r:HAS_ADDRESS]->(n)
ON CREATE SET r.classification = 'observed', r.derivation = 'asset_inventory'
"""

Q_IDENTITIES = """
UNWIND $rows AS i
MERGE (x:Identity {account_id: i.account_id})
ON CREATE SET x.account_type = i.account_type, x.home_host = i.home_host, x.in_inventory = true
ON MATCH SET x.in_inventory = true, x.account_type = coalesce(x.account_type, i.account_type)
"""

Q_EVENTS = """
UNWIND $rows AS e
MERGE (x:Event {event_id: e.event_id})
ON CREATE SET x.timestamp = e.timestamp, x.ts_epoch = e.ts_epoch, x.timestamp_original = e.timestamp_original,
  x.event_type = e.event_type, x.source = e.source, x.source_record_id = e.source_record_id,
  x.host_id = e.host_id, x.actor_id = e.actor_id, x.process_id = e.process_id,
  x.parent_process_id = e.parent_process_id, x.file_path = e.file_path, x.file_hash = e.file_hash,
  x.source_ip = e.source_ip, x.destination_ip = e.destination_ip, x.destination_port = e.destination_port,
  x.authentication_result = e.authentication_result, x.summary = e.raw_summary,
  x.raw_fields_json = e.raw_fields_json, x.ingested_at = $now, x.scenario_id = $scenario_id,
  x.image = e.image, x.parent_image = e.parent_image, x.command_line = e.command_line, x.signed = e.signed,
  x.alert_rule = e.alert_rule, x.severity = e.severity, x.alert_action = e.alert_action,
  x.sensor = e.sensor, x.sensor_status = e.sensor_status, x.change_id = e.change_id,
  x.logon_type = e.logon_type, x.access = e.access, x.protocol = e.protocol, x.bytes_out = e.bytes_out,
  x.approved_by = e.approved_by, x.auth_failure_reason = e.auth_failure_reason,
  x.window_start_epoch = e.window_start_epoch, x.window_end_epoch = e.window_end_epoch,
  x.warnings = e.warnings
"""

Q_ON_HOST = """
UNWIND $rows AS e
MATCH (x:Event {event_id: e.event_id})
MERGE (h:Host {host_id: e.host_id})
ON CREATE SET h.in_inventory = false
MERGE (x)-[r:ON_HOST]->(h)
ON CREATE SET r.classification = 'observed', r.derivation = 'field:host_id', r.evidence = [e.event_id]
"""

Q_ACTOR = """
UNWIND $rows AS e
MATCH (x:Event {event_id: e.event_id})
MERGE (i:Identity {account_id: e.actor_id})
ON CREATE SET i.in_inventory = false
MERGE (x)-[r:ACTOR]->(i)
ON CREATE SET r.classification = 'observed', r.derivation = 'field:actor_id', r.evidence = [e.event_id]
"""

Q_SPAWNED = """
UNWIND $rows AS e
MATCH (x:Event {event_id: e.event_id})
MERGE (p:Process {process_key: e.process_key})
ON CREATE SET p.pid = e.process_id, p.host_id = e.host_id
SET p.executable = e.image, p.command_line = e.command_line, p.parent_pid = e.parent_process_id,
    p.creation_observed = true, p.created_ts = e.ts_epoch
MERGE (x)-[r:SPAWNED]->(p)
ON CREATE SET r.classification = 'observed', r.derivation = 'process_creation_event', r.evidence = [e.event_id]
WITH p, e
MATCH (h:Host {host_id: e.host_id})
MERGE (p)-[r2:ON_HOST]->(h)
ON CREATE SET r2.classification = 'observed', r2.derivation = 'field:host_id', r2.evidence = [e.event_id]
"""

Q_PARENT = """
UNWIND $rows AS e
MATCH (p:Process {process_key: e.process_key})
MERGE (pp:Process {process_key: e.parent_key})
ON CREATE SET pp.pid = e.parent_process_id, pp.host_id = e.host_id, pp.creation_observed = false
MERGE (p)-[r:PARENT_PROCESS]->(pp)
ON CREATE SET r.classification = 'derived_from_field', r.derivation = 'field:parent_process_id',
              r.evidence = [e.event_id]
"""

Q_BY_PROCESS = """
UNWIND $rows AS e
MATCH (x:Event {event_id: e.event_id})
MERGE (p:Process {process_key: e.process_key})
ON CREATE SET p.pid = e.process_id, p.host_id = e.host_id, p.creation_observed = false
MERGE (x)-[r:BY_PROCESS]->(p)
ON CREATE SET r.classification = 'observed', r.derivation = 'field:process_id', r.evidence = [e.event_id]
"""

Q_FILE = """
UNWIND $rows AS e
MATCH (x:Event {event_id: e.event_id})
MERGE (f:File {path: e.file_path})
ON CREATE SET f.file_type = e.file_type
MERGE (x)-[r:ACCESSED_FILE]->(f)
ON CREATE SET r.classification = 'observed', r.derivation = 'field:file_path', r.evidence = [e.event_id],
              r.access = e.access, r.file_hash = e.file_hash
"""

Q_CONNECTED = """
UNWIND $rows AS e
MATCH (x:Event {event_id: e.event_id})
MERGE (n:NetworkEndpoint {ip: e.destination_ip})
MERGE (x)-[r:CONNECTED_TO]->(n)
ON CREATE SET r.classification = 'observed', r.derivation = 'field:destination_ip', r.evidence = [e.event_id],
              r.port = e.destination_port, r.protocol = e.protocol
"""

Q_FROM_ENDPOINT = """
UNWIND $rows AS e
MATCH (x:Event {event_id: e.event_id})
MERGE (n:NetworkEndpoint {ip: e.source_ip})
MERGE (x)-[r:FROM_ENDPOINT]->(n)
ON CREATE SET r.classification = 'observed', r.derivation = 'field:source_ip', r.evidence = [e.event_id]
"""

Q_AUTH_TO = """
UNWIND $rows AS e
MATCH (x:Event {event_id: e.event_id})
MATCH (h:Host {host_id: e.host_id})
MERGE (x)-[r:AUTHENTICATED_TO]->(h)
ON CREATE SET r.classification = 'observed', r.derivation = 'authentication_event_target_host',
              r.evidence = [e.event_id], r.result = e.authentication_result
"""

Q_COVERS = """
UNWIND $rows AS e
MATCH (x:Event {event_id: e.event_id})
MERGE (h:Host {host_id: e.covered_host})
ON CREATE SET h.in_inventory = false
MERGE (x)-[r:COVERS_HOST]->(h)
ON CREATE SET r.classification = 'observed', r.derivation = 'field:raw_fields.covered_hosts', r.evidence = [e.event_id]
"""

# Inference rule R1: an authentication's source_ip equals an address the asset inventory assigns to a host.
Q_R1_ORIGIN = """
MATCH (x:Event {event_type: 'authentication'})-[:FROM_ENDPOINT]->(n:NetworkEndpoint)<-[:HAS_ADDRESS]-(h:Host)
MERGE (x)-[r:ORIGINATED_FROM]->(h)
ON CREATE SET r.classification = 'inferred', r.derivation = 'rule:R1_source_ip_matches_inventory_address',
              r.evidence = [x.event_id], r.caveat = 'static inventory mapping; DHCP, NAT or spoofing could invalidate'
RETURN count(r) AS n
"""


def _file_type(path: str | None) -> str | None:
    if not path or "." not in path.rsplit("/", 1)[-1]:
        return None
    return path.rsplit(".", 1)[-1].lower()


def _epoch(value: Any) -> int | None:
    from app.ingestion.normalize import parse_timestamp
    if not isinstance(value, str):
        return None
    try:
        return parse_timestamp(value)[1]
    except ValueError:
        return None


def event_row(e: NormalizedEvent) -> dict[str, Any]:
    row = e.model_dump(exclude={"raw_fields"})
    row["raw_fields_json"] = json.dumps(e.raw_fields, sort_keys=True, default=str)[:8192]
    for k, prop in EXTRACT_RAW.items():
        v = e.raw_fields.get(k)
        row[prop] = v if isinstance(v, (str, int, float, bool)) else None
    row["window_start_epoch"] = _epoch(e.raw_fields.get("window_start"))
    row["window_end_epoch"] = _epoch(e.raw_fields.get("window_end"))
    if e.host_id and e.process_id is not None:
        row["process_key"] = f"{e.host_id}:{e.process_id}"
    if e.host_id and e.parent_process_id is not None:
        row["parent_key"] = f"{e.host_id}:{e.parent_process_id}"
    row["file_type"] = _file_type(e.file_path)
    return row


def _chunks(rows: list[dict], n: int = BATCH):
    for i in range(0, len(rows), n):
        yield rows[i:i + n]


class Stats:
    def __init__(self):
        self.nodes_created = 0
        self.relationships_created = 0
        self.properties_set = 0

    def add(self, res):
        self.nodes_created += res.nodes_created
        self.relationships_created += res.relationships_created
        self.properties_set += res.properties_set


def write_inventory(client: GraphClient, scenario_id: str, hosts: list[dict], identities: list[dict], stats: Stats):
    hrows = [{"host_id": str(h["host_id"]), "platform": h.get("platform"), "asset_role": h.get("asset_role"),
              "ip": h.get("ip")} for h in hosts if h.get("host_id")]
    irows = [{"account_id": str(i["account_id"]), "account_type": i.get("account_type"),
              "home_host": i.get("home_host")} for i in identities if i.get("account_id")]
    for chunk in _chunks(hrows):
        stats.add(client.run(scenario_id, Q_HOSTS, {"rows": chunk}, read_only=False))
    for chunk in _chunks(irows):
        stats.add(client.run(scenario_id, Q_IDENTITIES, {"rows": chunk}, read_only=False))


def write_events(client: GraphClient, scenario_id: str, events: list[NormalizedEvent], stats: Stats) -> int:
    rows = [event_row(e) for e in events]
    now = int(time.time())

    def run(q: str, subset: list[dict], **extra):
        for chunk in _chunks(subset):
            stats.add(client.run(scenario_id, q, {"rows": chunk, **extra}, read_only=False))

    run(Q_EVENTS, rows, now=now, scenario_id=scenario_id)
    run(Q_ON_HOST, [r for r in rows if r.get("host_id")])
    run(Q_ACTOR, [r for r in rows if r.get("actor_id")])
    pc = [r for r in rows if r["event_type"] == "process_creation" and r.get("process_key")]
    run(Q_SPAWNED, pc)
    run(Q_PARENT, [r for r in pc if r.get("parent_key")])
    run(Q_BY_PROCESS, [r for r in rows if r["event_type"] != "process_creation" and r.get("process_key")])
    run(Q_FILE, [r for r in rows if r.get("file_path")])
    run(Q_CONNECTED, [r for r in rows if r.get("destination_ip")])
    run(Q_FROM_ENDPOINT, [r for r in rows if r.get("source_ip")])
    run(Q_AUTH_TO, [r for r in rows if r["event_type"] == "authentication" and r.get("host_id")])
    covers = []
    for e in events:
        if e.event_type == "change_record":
            for h in e.raw_fields.get("covered_hosts") or []:
                if isinstance(h, str):
                    covers.append({"event_id": e.event_id, "covered_host": h})
    run(Q_COVERS, covers)
    res = client.run(scenario_id, Q_R1_ORIGIN, {}, read_only=False)
    stats.add(res)
    return len(rows)
