"""All investigative Cypher queries, parameterised and bounded.

Every query here is executed by FalkorDB. Python only orchestrates and applies documented rules
to the rows FalkorDB returns. Variable-length bounds must be literals in Cypher, so they are
formatted from a validated integer (never from user input).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.graph.client import GraphClient

# Order matters: Process nodes also carry host_id, so process_key must be tried before host_id.
KEY_EXPR = ("coalesce(n.event_id, n.process_key, n.hypothesis_id, n.investigation_id, n.account_id, "
            "n.path, n.ip, n.host_id)")
EVIDENCE_RELS = ("ON_HOST|ACTOR|SPAWNED|BY_PROCESS|PARENT_PROCESS|CONNECTED_TO|FROM_ENDPOINT|"
                 "ACCESSED_FILE|AUTHENTICATED_TO|ORIGINATED_FROM|HAS_ADDRESS|COVERS_HOST")

EVENT_COLS = ("e.event_id AS event_id, e.timestamp AS timestamp, e.ts_epoch AS ts_epoch, "
              "e.event_type AS event_type, e.source AS source, e.source_record_id AS source_record_id, "
              "e.host_id AS host_id, e.actor_id AS actor_id, e.summary AS summary")


@dataclass(frozen=True)
class Q:
    name: str
    purpose: str
    cypher: str


def _hops(n: int) -> int:
    n = int(n)
    if not 1 <= n <= 8:
        raise ValueError("hop bound out of range")
    return n


def catalog(max_hops: int = 4) -> dict[str, Q]:
    h = _hops(max_hops)
    qs = [
        Q("seed_candidates", "Find alert events that can seed an investigation (bounded, chronological).",
          f"""MATCH (e:Event {{event_type: 'edr_alert'}})
RETURN {EVENT_COLS}, e.severity AS severity, e.alert_rule AS rule, e.alert_action AS action, e.process_id AS pid
ORDER BY e.ts_epoch LIMIT $limit"""),
        Q("event_by_id", "Provenance of a single event: source, record id, timestamps, raw fields.",
          f"""MATCH (e:Event {{event_id: $event_id}})
RETURN {EVENT_COLS}, e.timestamp_original AS timestamp_original, e.raw_fields_json AS raw_fields_json,
       e.ingested_at AS ingested_at, e.warnings AS warnings"""),
        Q("process_lineage", "Multi-hop process ancestry of the seed event's process via PARENT_PROCESS.",
          f"""MATCH (seed:Event {{event_id: $event_id}})-[:SPAWNED|BY_PROCESS]->(p:Process)
MATCH path = (p)-[:PARENT_PROCESS*0..{h}]->(anc:Process)
OPTIONAL MATCH (ce:Event)-[:SPAWNED]->(anc)
RETURN anc.process_key AS process_key, anc.pid AS pid, anc.executable AS executable,
       anc.creation_observed AS creation_observed, length(path) AS depth,
       ce.event_id AS creation_event_id, ce.timestamp AS creation_ts, ce.parent_image AS parent_image,
       ce.signed AS signed
ORDER BY depth LIMIT $limit"""),
        Q("process_tree_activity", "Event chain: every event performed by the seed process or its descendants "
          "(PARENT_PROCESS traversal), with the files and network endpoints they touched.",
          # The explicit WITH DISTINCT stage pins the plan: a variant of this pattern without it was observed
          # to return no rows on FalkorDB 4.18.9 (see docs/VERIFICATION_REPORT.md); oracle-tested.
          f"""MATCH (seed:Event {{event_id: $event_id}})-[:SPAWNED|BY_PROCESS]->(p:Process)
MATCH (p)<-[:PARENT_PROCESS*0..{h}]-(d:Process)
WITH DISTINCT d
MATCH (e:Event)-[rel:SPAWNED|BY_PROCESS]->(d)
OPTIONAL MATCH (e)-[c:CONNECTED_TO]->(n:NetworkEndpoint)
OPTIONAL MATCH (e)-[:ACCESSED_FILE]->(f:File)
RETURN DISTINCT {EVENT_COLS}, d.process_key AS process_key, d.executable AS executable, type(rel) AS via,
       n.ip AS endpoint, c.port AS port, f.path AS file
ORDER BY ts_epoch LIMIT $limit"""),
        Q("host_actor_context", "Events by the same identity on the same host shortly before the seed "
          "(temporal context only - not treated as causal).",
          f"""MATCH (seed:Event {{event_id: $event_id}})-[:ON_HOST]->(hst:Host)
MATCH (seed)-[:ACTOR]->(i:Identity)
MATCH (e:Event)-[:ON_HOST]->(hst)
MATCH (e)-[:ACTOR]->(i)
WHERE e.ts_epoch >= seed.ts_epoch - $before_s AND e.ts_epoch <= seed.ts_epoch AND e.event_id <> seed.event_id
OPTIONAL MATCH (e)-[:ACCESSED_FILE]->(f:File)
RETURN {EVENT_COLS}, f.path AS file, f.file_type AS file_type
ORDER BY ts_epoch LIMIT $limit"""),
        Q("endpoint_prevalence", "Which hosts contacted a network endpoint, and whether the inventory owns it.",
          """MATCH (n:NetworkEndpoint {ip: $ip})<-[:CONNECTED_TO]-(e:Event)-[:ON_HOST]->(h:Host)
OPTIONAL MATCH (owner:Host)-[:HAS_ADDRESS]->(n)
RETURN h.host_id AS host_id, count(e) AS connections, collect(e.event_id)[0..20] AS event_ids,
       min(e.ts_epoch) AS first_seen, collect(DISTINCT owner.host_id) AS owners
ORDER BY first_seen LIMIT $limit"""),
        Q("cross_host_auth", "Cross-host pivot: authentications whose source address maps (rule R1) to the seed "
          "host, with target host and identity.",
          """MATCH (src:Host {host_id: $host_id})<-[o:ORIGINATED_FROM]-(a:Event)-[:AUTHENTICATED_TO]->(t:Host)
WHERE a.ts_epoch >= $t_from AND a.ts_epoch <= $t_to AND t.host_id <> $host_id
MATCH (a)-[:ACTOR]->(i:Identity)
RETURN a.event_id AS event_id, a.timestamp AS timestamp, a.ts_epoch AS ts_epoch, a.source AS source,
       a.source_record_id AS source_record_id, a.authentication_result AS result, a.logon_type AS logon_type,
       t.host_id AS target_host, t.asset_role AS target_role, i.account_id AS account, i.account_type AS account_type,
       i.home_host AS home_host, o.derivation AS derivation, o.classification AS classification, o.caveat AS caveat
ORDER BY ts_epoch LIMIT $limit"""),
        Q("identity_followon", "Multi-hop: Identity -> later events on the target host (what the credential did next).",
          f"""MATCH (i:Identity {{account_id: $account}})<-[:ACTOR]-(e:Event)-[:ON_HOST]->(t:Host {{host_id: $host_id}})
WHERE e.ts_epoch >= $t_from AND e.ts_epoch <= $t_to AND e.event_type <> 'authentication'
OPTIONAL MATCH (e)-[:ACCESSED_FILE]->(f:File)
RETURN {EVENT_COLS}, f.path AS file, e.access AS access
ORDER BY ts_epoch LIMIT $limit"""),
        Q("identity_baseline", "How an identity normally authenticates: origin hosts (rule R1) and counts.",
          """MATCH (i:Identity {account_id: $account})<-[:ACTOR]-(a:Event {event_type: 'authentication'})
WHERE a.ts_epoch < $before
OPTIONAL MATCH (a)-[:ORIGINATED_FROM]->(src:Host)
WITH coalesce(src.host_id, 'unmapped:' + coalesce(a.source_ip, 'none')) AS origin, a
RETURN origin, count(a) AS n, collect(a.event_id)[0..20] AS event_ids, min(a.ts_epoch) AS first_ts,
       max(a.ts_epoch) AS last_ts
ORDER BY n DESC LIMIT $limit"""),
        Q("change_records_at", "Approved change records active at a time, with the hosts they cover.",
          """MATCH (c:Event {event_type: 'change_record'})
WHERE c.window_start_epoch <= $ts AND c.window_end_epoch >= $ts
OPTIONAL MATCH (c)-[:COVERS_HOST]->(h:Host)
RETURN c.event_id AS event_id, c.change_id AS change_id, c.summary AS summary, c.source AS source,
       c.source_record_id AS source_record_id, c.timestamp AS timestamp, c.approved_by AS approved_by,
       collect(h.host_id) AS covered_hosts
ORDER BY event_id LIMIT $limit"""),
        Q("host_telemetry_coverage", "Telemetry sources present for a host and their time span.",
          """MATCH (e:Event)-[:ON_HOST]->(h:Host {host_id: $host_id})
RETURN e.source AS source, count(e) AS n, min(e.ts_epoch) AS first_ts, max(e.ts_epoch) AS last_ts
ORDER BY source"""),
        Q("sensor_status", "Sensor heartbeat lost/restored events for a host (explicit telemetry gaps).",
          """MATCH (e:Event {event_type: 'telemetry_status'})-[:ON_HOST]->(h:Host {host_id: $host_id})
RETURN e.event_id AS event_id, e.timestamp AS timestamp, e.ts_epoch AS ts_epoch, e.sensor AS sensor,
       e.sensor_status AS status, e.source AS source, e.source_record_id AS source_record_id
ORDER BY ts_epoch LIMIT $limit"""),
        Q("source_events_in_window", "Events from one telemetry source on a host within a time window.",
          """MATCH (e:Event)-[:ON_HOST]->(h:Host {host_id: $host_id})
WHERE e.source = $source AND e.ts_epoch >= $t_from AND e.ts_epoch <= $t_to
RETURN count(e) AS n"""),
        Q("auth_by_host_role", "Which host roles contributed authentication telemetry (e.g. domain controller).",
          """MATCH (e:Event {event_type: 'authentication'})-[:ON_HOST]->(h:Host)
RETURN coalesce(h.asset_role, 'unknown') AS role, count(e) AS n ORDER BY role"""),
        Q("timeline_window", "Bounded timeline: events in a time interval, optionally restricted to hosts.",
          f"""MATCH (e:Event)
WHERE e.ts_epoch >= $t_from AND e.ts_epoch <= $t_to AND ($hosts IS NULL OR e.host_id IN $hosts)
RETURN {EVENT_COLS}
ORDER BY ts_epoch, event_id LIMIT $limit"""),
        Q("timeline_by_ids", "Ordered timeline for an explicit evidence set.",
          f"""MATCH (e:Event) WHERE e.event_id IN $ids
RETURN {EVENT_COLS}
ORDER BY ts_epoch, event_id LIMIT $limit"""),
        # NOTE: FalkorDB 4.18 rejects shortestPath inside MATCH and does not support undirected
        # shortestPath (both verified against the running server), so the cross-host chain is an
        # explicit directed multi-hop pattern instead.
        Q("evidence_path", "Explicit cross-host evidence chain: seed -ON_HOST-> host <-ORIGINATED_FROM- "
          "authentication -AUTHENTICATED_TO-> target host, -ACTOR-> identity.",
          """MATCH (a:Event {event_id: $a})-[r1:ON_HOST]->(h:Host)<-[r2:ORIGINATED_FROM]-(b:Event {event_id: $b})
MATCH (b)-[r3:AUTHENTICATED_TO]->(t:Host)
MATCH (b)-[r4:ACTOR]->(i:Identity)
RETURN [a.event_id, h.host_id, b.event_id, t.host_id, i.account_id] AS nodes,
       ['Event', 'Host', 'Event', 'Host', 'Identity'] AS labels,
       [type(r1), type(r2), type(r3), type(r4)] AS rels,
       [r1.classification, r2.classification, r3.classification, r4.classification] AS classes,
       r2.derivation AS inference_rule"""),
        Q("hypothesis_provenance", "Trace a stored hypothesis to the source events that support/contradict it.",
          """MATCH (hy:Hypothesis {hypothesis_id: $hypothesis_id})<-[r:SUPPORTS|CONTRADICTS]-(e:Event)
RETURN type(r) AS relation, r.rule AS rule, r.rationale AS rationale, e.event_id AS event_id,
       e.timestamp AS timestamp, e.source AS source, e.source_record_id AS source_record_id, e.summary AS summary
ORDER BY relation, timestamp, event_id LIMIT $limit"""),
        Q("subgraph_for_events", "Nodes and typed relationships around an evidence set (for visualisation).",
          f"""MATCH (e:Event)-[r:{EVIDENCE_RELS}]->(n)
WHERE e.event_id IN $ids
RETURN e.event_id AS src, type(r) AS rel, r.classification AS classification, labels(n)[0] AS dst_label,
       {KEY_EXPR} AS dst LIMIT $limit"""),
        Q("process_edges_for_keys", "PARENT_PROCESS edges among processes in the evidence set.",
          """MATCH (p:Process)-[r:PARENT_PROCESS]->(pp:Process)
WHERE p.process_key IN $keys
RETURN p.process_key AS child, pp.process_key AS parent, r.classification AS classification,
       r.evidence AS evidence LIMIT $limit"""),
        Q("counts", "Node and relationship counts by label/type.",
          """MATCH (n) RETURN labels(n)[0] AS label, count(n) AS n ORDER BY label"""),
        Q("rel_counts", "Relationship counts by type and classification.",
          """MATCH ()-[r]->() RETURN type(r) AS type, r.classification AS classification, count(r) AS n
ORDER BY type"""),
        Q("events_list", "Paged list of normalised events.",
          f"""MATCH (e:Event) WHERE ($event_type IS NULL OR e.event_type = $event_type)
AND ($host_id IS NULL OR e.host_id = $host_id)
RETURN {EVENT_COLS}, e.raw_fields_json AS raw_fields_json
ORDER BY ts_epoch, event_id SKIP $skip LIMIT $limit"""),
        Q("existing_event_ids", "Which of the given event ids exist in the graph (provenance validation).",
          """MATCH (e:Event) WHERE e.event_id IN $ids RETURN collect(e.event_id) AS ids"""),
    ]
    return {q.name: q for q in qs}


class GraphQueries:
    def __init__(self, client: GraphClient, scenario_id: str):
        self.client = client
        self.scenario_id = scenario_id
        self.limit = client.settings.result_limit
        self.cat = catalog(client.settings.max_hops)
        self.log: list[dict[str, Any]] = []  # executed query audit trail

    def run(self, name: str, **params) -> list[dict[str, Any]]:
        q = self.cat[name]
        params.setdefault("limit", self.limit)
        rows = self.client.rows(self.scenario_id, q.cypher, params)
        self.log.append({"query": name, "purpose": q.purpose,
                         "params": {k: v for k, v in params.items() if k != "limit"}, "rows": len(rows)})
        return rows
