# IncidentZero

**Graph-Powered Digital Forensics for Cyber Incident Reconstruction from connected evidence.**

<img width="1774" height="887" alt="IncidentZero Forensic Graph Dashboard" src="https://github.com/user-attachments/assets/7594538d-22e0-4f0d-998a-430d2625e5f9" />


IncidentZero helps an investigator move beyond a flat list of alerts. It connects events across processes, hosts, identities, files, and network endpoints; reconstructs evidence chains; compares competing explanations; and makes uncertainty visible. Each factual finding points back to source event IDs, while inferred relationships identify the rule that created them.

---

## Contents

- [The problem](#the-problem)
- [The IncidentZero approach](#the-incidentzero-approach)
- [What makes the graph essential](#what-makes-the-graph-essential)
- [Features](#features)
- [Architecture and data flow](#architecture-and-data-flow)
- [Graph data model](#graph-data-model)
- [Representative Cypher queries](#representative-cypher-queries)
- [Synthetic dataset](#synthetic-dataset)
- [Investigation methodology](#investigation-methodology)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [API overview](#api-overview)
- [Security, privacy, and limitations](#security-privacy-and-limitations)
- [Project structure](#project-structure)
- [AI-assistance disclosure](#ai-assistance-disclosure)
- [License](#license)

---

## The problem

A security alert rarely tells the complete story. An endpoint may report a suspicious process, but an investigator still needs to determine what launched it, what the process accessed, which network endpoints it contacted, whether an identity subsequently appeared on another host, and whether that activity is consistent with normal operations.

Those clues usually arrive as separate records from endpoint, authentication, network, and file telemetry. Looking at each record independently—or simply sorting every record by timestamp—can miss relationships that span multiple event sources and hosts. Conversely, connecting events solely because they occurred close together can create a false narrative: **temporal order is not proof of causation**.

The central problem IncidentZero addresses is:

> **Given incomplete and partly ambiguous security telemetry, how can an investigator reconstruct the strongest evidence-supported incident narrative, compare plausible alternatives, and identify what evidence is still needed, without turning correlation into an unsupported claim of causation?**

IncidentZero is designed as an investigation assistant, not an autonomous incident-response system. It helps answer *what is connected, what supports each explanation, what contradicts it, and what should be checked next*. It does not declare an attacker’s identity or a definitive root cause when the available evidence cannot justify that conclusion.

## The IncidentZero approach

IncidentZero treats an incident as a connected evidence problem.

1. **Ingest telemetry.** Read JSON/JSONL scenario data, validate records, normalise timestamps and fields, report rejected records, and handle duplicates.
2. **Build the evidence graph.** Write typed event and entity nodes to FalkorDB and connect them using observed, field-derived, or explicitly rule-inferred relationships.
3. **Traverse relationships.** Use parameterised Cypher queries to follow process lineage, inspect process-tree activity, pivot across hosts through identities, compare identity origins, and investigate endpoint prevalence.
4. **Compare explanations.** Evaluate a compromise hypothesis against an authorised-administration/maintenance alternative using documented, inspectable rules.
5. **Expose uncertainty.** Show supporting observations, contradictory evidence, assumptions, missing telemetry, and qualitative confidence rationale.
6. **Recommend the next evidence.** Identify a log source, record, or validation step that could distinguish the hypotheses.
7. **Produce an auditable report.** Export JSON or Markdown findings with source-event IDs and provenance.

The MVP is deterministic: the same scenario and investigation request produce reproducible results. An LLM is not required as of now for MVP, for the investigation pipeline, avoiding a dependency on API credentials and reducing the risk of generated explanations introducing unsupported evidence.

## What makes the graph essential

FalkorDB is not being used only to draw a network diagram. The investigation engine relies on its stored graph and Cypher traversals to retrieve the evidence used in findings.

For example, a process investigation can begin at a seed event, traverse to the process that generated it, follow parent-process relationships, and retrieve activity attributed to those processes. A separate investigation can pivot from an authentication event through its inferred origin host, identity, and target host, then compare that origin with the identity’s historical baseline.

The graph enables these multi-hop relationships to be queried consistently across the event set. If FalkorDB is unavailable, a new graph-backed investigation fails with **HTTP 503**; the API does not substitute hard-coded answers, a mock graph, or an in-memory graph traversal. This no-fallback behaviour is covered by tests, including a test for a database that becomes unavailable after the API has connected.

The graph also stores investigation and hypothesis provenance. Findings can be traced back to source events, and inferred edges record the rule and evidence behind their creation.

## Features

- **Synthetic incident scenarios:** three fictional cases covering suspected compromise, benign administrative activity, and incomplete evidence.
- **Validated ingestion:** typed normalisation, timestamp checks, duplicate handling, warnings, and explicit rejection reasons.
- **Idempotent graph loading:** reloading the same scenario does not create duplicate event nodes or semantic relationships.
- **Graph-native investigation:** bounded, parameterised Cypher queries for lineage, process activity, identity pivots, endpoint prevalence, timelines, and provenance.
- **Competing hypotheses:** compromise versus authorised administration/maintenance, with supporting and contradictory evidence.
- **Uncertainty and telemetry gaps:** unknowns are represented explicitly; inconclusive outcomes are possible and intentional.
- **Next-evidence recommendations:** suggested logs or validation checks that can distinguish competing explanations.
- **Evidence-linked reporting:** JSON and Markdown reports use source event IDs.
- **Investigation console:** a browser-based interface served by FastAPI and populated by live API results.
- **Evaluation tooling:** compares results against separate synthetic ground-truth labels and includes a simple non-traversal baseline.
- **No response actions:** the system does not scan hosts, execute collected commands or files, use credentials, or perform containment.

## Architecture and data flow

IncidentZero is a modular monolith: one FastAPI process serves the API and static browser console, while FalkorDB stores the graph and investigation records.

```text
Synthetic JSON/JSONL scenarios
              |
              v
     Validation and normalisation
              |
              v
       Idempotent graph writer
              |
              v
            FalkorDB
              |
              v
    Parameterised Cypher traversals
              |
              v
    Deterministic investigation rules
              |
              +--> Timeline and evidence chain
              +--> Competing hypotheses
              +--> Contradictions and unknowns
              +--> Next-evidence recommendations
              |
              v
       FastAPI investigation API
              |
              +--> Browser console
              +--> JSON report
              +--> Markdown report
```

### Component responsibilities

- **Ingestion and normalisation:** validates event shape, parses timestamps, rejects invalid records, handles duplicates, preserves source identifiers, and records warnings.
- **Graph writer:** creates indexes, writes inventory and event data using idempotent graph operations, and adds relationship classification and provenance.
- **Graph query catalogue:** provides named, parameterised Cypher queries with bounded traversals, result limits, and query timeouts.
- **Investigation engine:** selects a seed and time window, retrieves graph evidence, applies documented rules, reconstructs a timeline, identifies unknowns, recommends next evidence, and persists the investigation.
- **API:** exposes scenario loading, ingestion, investigation, evidence, graph, timeline, hypothesis, report, and health endpoints.
- **Browser console:** displays live API results, hypotheses, timelines, evidence chains, telemetry gaps, and report exports.


## Graph data model

Graph name: `incidentzero_<dataset_id>`. The prefix can be changed with `INCIDENTZERO_GRAPH_PREFIX`.

### Node types

| Node | Key | Purpose and representative properties |
|---|---|---|
| `Event` | `event_id` | A normalised source record: `timestamp`, `ts_epoch`, `timestamp_original`, `event_type`, `source`, `source_record_id`, host/account/process fields, network/file fields, raw fields, and warnings |
| `Host` | `host_id` | Fictional workstation or server: platform, asset role, address, inventory status |
| `Identity` | `account_id` | Account mentioned in telemetry: account type, home host, inventory status |
| `Process` | `process_key` (`host:pid`) | Process: PID, host ID, executable, command line, parent PID, creation-observed flag, creation timestamp |
| `File` | `path` | File referenced by an event, with optional file type and hash where supplied |
| `NetworkEndpoint` | `ip` | IP endpoint; port and protocol are represented where appropriate on events or relationships |
| `Investigation` | `investigation_id` | Saved investigation: name, creation time, assessment, and result JSON |
| `Hypothesis` | `hypothesis_id` (for example, `<investigation_id>:H1`) | Explanation being assessed: kind, description, status, confidence label, and rationale |

The application creates range indexes for frequently queried properties such as event ID, event type, timestamp, source, host ID, account ID, process key, file path, endpoint IP, investigation ID, and hypothesis ID.

### Important relationships and their semantics

| Relationship | Meaning | Classification |
|---|---|---|
| `Event-[:ON_HOST]->Host` | Event was recorded on a host | Observed from event fields |
| `Event-[:ACTOR]->Identity` | Event names an account | Observed from event fields |
| `Event-[:SPAWNED]->Process` | Process-creation event created the process | Observed from event fields |
| `Event-[:BY_PROCESS]->Process` | Event is attributed to a process | Observed from event fields |
| `Process-[:PARENT_PROCESS]->Process` | Parent-child process relationship | Derived from `parent_process_id` |
| `Event-[:ACCESSED_FILE]->File` | Event references a file | Observed from event fields |
| `Event-[:CONNECTED_TO]->NetworkEndpoint` | Event records a destination connection | Observed from event fields |
| `Event-[:FROM_ENDPOINT]->NetworkEndpoint` | Event records a source endpoint | Observed from event fields |
| `Event-[:AUTHENTICATED_TO]->Host` | Authentication targets a host | Observed from event fields |
| `Host-[:HAS_ADDRESS]->NetworkEndpoint` | Inventory maps an address to a host | Observed from synthetic inventory |
| `Event-[:ORIGINATED_FROM]->Host` | Authentication origin inferred from source IP matching an inventory address | Inferred by rule `R1` |
| `Event-[:SUPPORTS]->Hypothesis` | Evidence supports a hypothesis under a named rule | Inferred by investigation rules |
| `Event-[:CONTRADICTS]->Hypothesis` | Evidence contradicts a hypothesis under a named rule | Inferred by investigation rules |
| `Hypothesis-[:DERIVED_FROM]->Event` | Hypothesis is associated with its investigation seed | Investigation provenance |
| `Investigation-[:HAS_EVENT]->Event` | Event belongs to an investigation scope | Investigation-scope relationship |
| `Investigation-[:HAS_HYPOTHESIS]->Hypothesis` | Hypothesis belongs to an investigation | Investigation-scope relationship |

Evidence relationships preserve their classification, derivation, and supporting event references. Relationships are classified as:

- **Observed:** stated directly by a source event or inventory field.
- **Derived from field:** created from an explicit reference field, such as `parent_process_id`.
- **Inferred:** produced by a named rule over several facts.
- **Investigation scope:** records which events and hypotheses belong to an investigation.

If a parent process was never observed being created, its `Process` node can exist with `creation_observed=false`. The graph preserves this as a gap instead of fabricating a process-creation event.

**Temporal order is not causality.** No edge is created from timestamps alone. `FOLLOWED_BY` is intentionally absent. Timelines are produced by sorting timestamps, and events retrieved because they occurred near another event are labelled as temporal context rather than causal evidence.

### Example graph counts

In the recorded scenario 001 investigation, a live FalkorDB query reported 144 `Event` nodes, 33 `Process` nodes, 18 `File` nodes, 10 `NetworkEndpoint` nodes, 6 `Host` nodes, and 6 `Identity` nodes. Relationship counts change as the graph is loaded and investigations are persisted.

## Representative Cypher queries

The application maintains a larger query catalogue in `app/graph/queries.py`. These representative examples show the investigative purpose of graph traversal. The live application uses parameterised queries, bounded traversals, and configured result/time limits.

### 1. Process lineage

**Question:** What processes are ancestors of the process associated with a suspicious event?

```cypher
MATCH (seed:Event {event_id: $event_id})-[:SPAWNED|BY_PROCESS]->(p:Process)
MATCH path = (p)-[:PARENT_PROCESS*0..4]->(anc:Process)
OPTIONAL MATCH (ce:Event)-[:SPAWNED]->(anc)
RETURN anc.process_key AS process_key,
       anc.executable AS executable,
       length(path) AS depth,
       ce.event_id AS creation_event_id
ORDER BY depth
LIMIT $limit
```

The result supports process-lineage rules and gives the investigator source events for observed process creation where available. A missing creation record remains a telemetry gap; it is not filled in by assumption.

### 2. Cross-host authentication pivot

**Question:** Did an identity associated with the seed host authenticate to another host from an origin mapped to that host?

```cypher
MATCH (src:Host {host_id: $host_id})<-[o:ORIGINATED_FROM]-(a:Event)-[:AUTHENTICATED_TO]->(t:Host)
WHERE a.ts_epoch >= $t_from
  AND a.ts_epoch <= $t_to
  AND t.host_id <> $host_id
MATCH (a)-[:ACTOR]->(i:Identity)
RETURN a.event_id AS event_id,
       a.authentication_result AS result,
       t.host_id AS target_host,
       i.account_id AS account,
       o.derivation AS derivation,
       o.classification AS classification
ORDER BY a.ts_epoch
LIMIT $limit
```

The `ORIGINATED_FROM` edge is inferred by rule `R1` when an authentication's source IP matches an inventory address. The result is an investigative link, not proof of the human actor or of compromise.

### 3. Identity baseline

**Question:** What origins were previously observed for this account?

```cypher
MATCH (i:Identity {account_id: $account})<-[:ACTOR]-(a:Event {event_type: 'authentication'})
WHERE a.ts_epoch < $before
OPTIONAL MATCH (a)-[:ORIGINATED_FROM]->(src:Host)
WITH coalesce(src.host_id, 'unmapped:' + coalesce(a.source_ip, 'none')) AS origin, a
RETURN origin,
       count(a) AS n,
       collect(a.event_id)[0..20] AS event_ids
ORDER BY n DESC
LIMIT $limit
```

This query supplies context for evaluating whether an authentication origin is unusual relative to the synthetic evidence available before the investigation window. It does not establish whether the activity is malicious.

### 4. Hypothesis provenance

**Question:** Which source records support or contradict a saved hypothesis, and under which rule?

```cypher
MATCH (hy:Hypothesis {hypothesis_id: $hypothesis_id})<-[r:SUPPORTS|CONTRADICTS]-(e:Event)
RETURN type(r) AS relation,
       r.rule AS rule,
       e.event_id AS event_id,
       e.source AS source,
       e.source_record_id AS source_record_id
```

This lets a reviewer trace an assessed explanation back to its source records.

### Additional graph queries

The query catalogue also includes:

| Query | Investigative question |
|---|---|
| `seed_candidates` | Which alerts can seed an investigation? |
| `event_by_id` | What exactly did the source record say? |
| `process_lineage` | What launched the process, up to four hops? |
| `process_tree_activity` | What did the process and its descendants do, including file and endpoint activity? |
| `host_actor_context` | What did the same user do on the host shortly before the seed? This is temporal context only. |
| `endpoint_prevalence` | Which hosts contacted this endpoint, and does inventory own it? |
| `cross_host_auth` | Which authentications originated from the seed host and targeted other hosts? |
| `identity_followon` | What did the identity do on the target host afterwards? |
| `identity_baseline` | From which hosts does this identity normally authenticate in the available evidence? |
| `change_records_at` | Was an approved change active, and which hosts did it cover? |
| `host_telemetry_coverage`, `sensor_status`, `auth_by_host_role` | Which telemetry exists, and where are the gaps? |
| `timeline_window`, `timeline_by_ids` | Retrieve bounded, ordered timelines |
| `evidence_path` | Retrieve an explicit cross-host chain from seed to authentication, target, and identity |
| `hypothesis_provenance` | Retrieve events supporting or contradicting a stored hypothesis |
| `subgraph_for_events`, `process_edges_for_keys` | Retrieve graph data for evidence visualisation |

All catalogue queries are exercised by the graph integration test suite in the recorded verification run.

## Synthetic dataset

The repository contains three scenarios generated by `scripts/generate_dataset.py`. The current dataset contains **256 raw event records** across the scenarios, with fictional hosts, identities, process activity, authentication events, file events, network activity, alerts, and deliberately incomplete telemetry.

| Scenario | Intended outcome | What it tests |
|---|---|---|
| `scenario_001` | Compromise is favoured, not confirmed | Multi-host investigation, process lineage, identity baseline, contradictory context, and sensor gaps |
| `scenario_002` | Benign administration is favoured | Whether known administrative context can contradict a compromise explanation |
| `scenario_003` | Inconclusive | Whether the system exposes uncertainty when evidence and telemetry are incomplete |

All event details are fictional and generated for the invented organisation **Kestrel Ridge Analytics**. External IPs use documentation ranges. No real security logs, credentials, private records, or personal data are included.

### Dataset quality and ingestion

The dataset validator checks scenario structure, event IDs, timestamps, entity references, ground-truth references, and consistency requirements. The event normaliser validates types, rejects malformed or incomplete records, preserves source identifiers, and reports warnings. Duplicate event IDs are handled deliberately; conflicting duplicates are not silently treated as new independent evidence.

Ground truth is stored separately under `evaluation/ground_truth/`. It contains intended explanations and evaluation labels; it is not a source of evidence for the investigation engine. Because this repository is public, this separation prevents accidental use through the normal engine code path but does not prevent a person from reading the files.


## Investigation methodology

The engine is deterministic: the same graph and investigation request produce the same result and investigation identifier. The investigation identifier is derived from the scenario, seed, time window, and question.

### Investigation pipeline

1. **Scope the investigation.** Select a seed from an explicit `seed_event_id`, an event ID in the question, or the earliest highest-severity eligible EDR alert. If the question names a host, that context is preferred. The default investigation window is 60 minutes.
2. **Retrieve connected evidence.** Query the seed event, process lineage, process-tree activity, and same-user context before the seed.
3. **Pivot across the graph.** Retrieve endpoint prevalence, cross-host authentications from the seed host through rule `R1`, identity baselines, follow-on activity, and explicit evidence paths.
4. **Check operational context.** Inspect change records, sensor status, host telemetry coverage, and available authentication sources.
5. **Evaluate competing hypotheses.** Apply documented rules to support, contradictions, and unknowns.
6. **Reconstruct the timeline.** Sort the selected evidence by timestamp and expose gaps, including gaps greater than 30 minutes.
7. **Recommend next evidence.** Produce recommendations for unresolved questions and for verifying inferred relationships such as `R1`.
8. **Audit provenance.** Check that every referenced event ID exists in FalkorDB, then persist the investigation and hypothesis provenance.

### Finding types

- **Observation:** restates one or more source events and includes their event IDs.
- **Inference:** a named rule applied to observations, with event IDs and a rule ID.
- **Contradiction:** evidence against a hypothesis, with event IDs and a rule ID.
- **Unknown:** missing telemetry or a question the available data cannot determine. An unknown may have no event IDs because it describes an absence of evidence.

The provenance check verifies that observations, inferences, and contradictions cite at least one event ID that exists in FalkorDB. Unsupported findings are counted by the evaluator.

### Investigation rules

| Rule | Effect | Weight | Definition |
|---|---|---:|---|
| `R1` | Inferred edge | — | Authentication `source_ip` equals a host inventory address, so an `ORIGINATED_FROM` edge is created. This has a DHCP/NAT caveat. |
| `C1` | Supports H1; contradicts H2 | 2 | An office/document application is an ancestor of a script interpreter. |
| `C2` | Supports H1; contradicts H2 | 2 | The seed process tree wrote an executable-type file. |
| `C3` | Supports H1 | 1 | The process tree contacted a non-private, non-inventory endpoint. |
| `C4` | Supports H1; contradicts H2 | 2 | An identity authenticated from the seed host even though its baseline shows only other origins. |
| `C5` | Supports H1 | 1 | Authentication failure was followed by success for the same identity and origin, only when `C4` holds. |
| `C6` | Supports H1 | 1 | File access occurred on the target after an out-of-baseline authentication. |
| `C7` | Supports H1 | 1 | Hidden-window or encoded-command flags appear on the seed process command line. |
| `X1` | Contradicts H1; supports H2 | 2 | An approved change record covers the seed host at the seed time. |
| `X2` | Contradicts H1; supports H2 | 1 | Other hosts also contacted the same external endpoint. |
| `X3` | Weakly contradicts H1 | 0.5 | Alert severity is not high and the alert is allowed by the relevant control. |
| `X4` | Contradicts H1; supports H2 | 2 | The identity baseline already includes the origin. |
| `X5` | Contradicts H1; supports H2 | 1 | The script interpreter was launched by signed administrative tooling rather than a document application. |
| `M1` | Unknown | — | EDR sensor was offline during the seed or cross-host activity. |
| `M2` | Unknown | — | Domain-controller authentication logs are absent when cross-host authentication is involved. |
| `M3` | Unknown | — | The immediate parent process has no creation record. |
| `M4` | Unknown | — | No authentication telemetry is available. |

H1 represents a compromise explanation; H2 represents authorised administration or maintenance. These are scenario-level hypotheses, not universal categories for all security incidents.

### Qualitative confidence and outcome

Confidence is qualitative, not a calibrated probability:

- **High:** support score is at least 4, contradictions are no more than half the support score, and no evidence gaps remain.
- **Moderate:** the same support/contradiction condition holds, but missing evidence remains.
- **Low-to-moderate:** support is at least 2 and contradictions are fewer than support.
- **Low:** anything else.

The final assessment is **inconclusive** if the best net score leads the alternative by less than 2, if the best support score is below 2, or if support is below 4 while at least two unknowns remain. Otherwise the outcome is `compromise_likely` or `benign_likely`.

Results are phrased as **favoured, not confirmed**. The system does not infer intent, identify a person from an IP address, explain how a credential was obtained, or treat chronology as proof of causation.

## Quick start

IncidentZero requires **Python 3.11** and **FalkorDB 4.18 or later on Redis 8 or later** for the verified configuration. You can use Docker Compose or connect the Python application to a compatible local FalkorDB server.

### Option A: Docker Compose

Prerequisites: Docker Engine/Desktop with the Compose plugin and network access to obtain the configured container images.

```bash
# Copy the example configuration if you want a local .env file
cp .env.example .env

# Build the API image and start FalkorDB + API
docker compose up --build -d
```

In this case, Load all three synthetic scenarios through the application loader separately.

Open:
- Console: `http://localhost:8000`
- API documentation: `http://localhost:8000/docs`

**Verification note:** the Docker Compose path is included but was **not executed in the original verification environment**, because the Docker daemon and registry access were unavailable. The image tag and container health check therefore remain unverified. Do not interpret the commands above as proof that Compose has been tested. The verified server was FalkorDB v4.18.9 built from source with Redis 8.0.6.

To stop the stack:

```bash
docker compose down
```

Inspect the Compose configuration before removing volumes or database state; deleting volumes can remove persistent data.

### Option B: Local Python application

Start a compatible FalkorDB server first. For example, if Docker is available:

```bash
docker run --name incidentzero-falkordb -p 6379:6379 -d falkordb/falkordb:latest
```

The `latest` tag is mutable and the exact image command was not verified in the original environment. Use a compatible, trusted image/version for your machine.


#### Linux/macOS

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

cp .env.example .env
python -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/` for the console and `http://127.0.0.1:8000/docs` for interactive API documentation. Keep the server process running while using the console.

The commands assume a compatible FalkorDB service is reachable at the configured host and port. If the database is unavailable, graph-backed endpoints should return a dependency error rather than fabricate results.


## Configuration

Configuration is environment-based. `.env.example` contains placeholders, not real credentials.

| Variable | Purpose | Default/notes |
|---|---|---|
| `FALKORDB_HOST` | FalkorDB host | `localhost` for a local Python process; Compose overrides it to `falkordb` |
| `FALKORDB_PORT` | FalkorDB port | `6379` |
| `FALKORDB_USERNAME` | Optional database username | Usually unset for a local demo |
| `FALKORDB_PASSWORD` | Optional database password | Usually unset for a local demo |
| `INCIDENTZERO_GRAPH_PREFIX` | Prefix for per-scenario graph names | `incidentzero_` |
| `INCIDENTZERO_QUERY_TIMEOUT_MS` | Graph query timeout | `5000` ms |
| `INCIDENTZERO_RESULT_LIMIT` | Maximum query result limit | `500` |
| `INCIDENTZERO_MAX_INGEST_RECORDS` | Maximum records per ingestion request | `5000` |
| `INCIDENTZERO_MAX_HOPS` | Maximum traversal depth | `4` |
| `INCIDENTZERO_SOCKET_TIMEOUT_S` | Database socket timeout | `10` seconds |
| `INCIDENTZERO_SCENARIO_ROOT` | Optional scenario directory override | Must point only to scenario data, never the evaluator directory |

Never commit a real `.env` file, credentials, or private telemetry. Do not expose the unauthenticated local demo API to the public internet without adding appropriate authentication, authorisation, transport security, and operational controls.

## API overview

FastAPI exposes interactive OpenAPI documentation at `/docs` and the schema at `/openapi.json`.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Application/dependency health |
| `GET` | `/` | Browser investigation console |
| `GET` | `/api/scenarios` | List bundled scenarios |
| `POST` | `/api/scenarios/{scenario_id}/load` | Load or reset a scenario into FalkorDB |
| `POST` | `/api/events/ingest` | Ingest validated event records |
| `GET` | `/api/events` | List/query events |
| `GET` | `/api/events/{id}` | Retrieve one event |
| `GET` | `/api/investigations` | List saved investigations |
| `POST` | `/api/investigations` | Start an investigation |
| `GET` | `/api/investigations/{id}` | Retrieve an investigation result |
| `GET` | `/api/investigations/{id}/timeline` | Retrieve the evidence timeline |
| `GET` | `/api/investigations/{id}/evidence` | Retrieve evidence and provenance |
| `GET` | `/api/investigations/{id}/hypotheses` | Retrieve hypotheses and supporting/contradicting events |
| `GET` | `/api/investigations/{id}/graph` | Retrieve graph data for exploration |
| `POST` | `/api/investigations/{id}/next-evidence` | Retrieve/recompute next-evidence recommendations |
| `GET` | `/api/investigations/{id}/report` | Export JSON or Markdown report |
| `GET` | `/api/queries` | Inspect the query catalogue |

Exact request/response schemas are available through `/docs`. The API returns meaningful errors for invalid or unknown resources. In particular, FalkorDB unavailability returns HTTP **503**, and graph query failures return **502**. The engine does not silently fall back to fabricated data.


## Security, privacy, and limitations

### Safety and data handling

- Only synthetic or otherwise explicitly authorised data should be used.
- The included fixtures use fictional hosts, accounts, paths, and records; external IPs use documentation ranges.
- The application does not execute collected files or commands, use credentials, scan live hosts, or take containment actions.
- Input is validated and bounded; queries are parameterised, traversals are limited, and graph queries use a configured timeout.
- Raw event content is not intentionally logged as application output. Do not ingest sensitive data into a demo deployment.
- Do not expose the unauthenticated local demo API to the public internet without adding suitable authentication, authorisation, transport security, and operational controls.


## Project structure

```text
incidentzero/
├── app/
│   ├── api/                 # FastAPI routes and console serving
│   ├── graph/               # FalkorDB client, schema, writer, Cypher queries
│   ├── ingestion/           # Event validation, normalisation, loading
│   ├── investigation/       # Deterministic investigation engine and rules
│   ├── models/              # Request/response schemas
│   └── reporting/           # JSON and Markdown reports
├── data/
│   └── scenarios/           # Three synthetic scenarios and raw event fixtures
├── frontend/                # Static browser console
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── .dockerignore
├── .gitignore
├── LICENSE
└── README.md
```


## License

This project includes an MIT `LICENSE` file. Review the license file and the licences of dependencies before redistributing third-party components.
