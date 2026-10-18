"""FastAPI application. OpenAPI docs at /docs."""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from app.config import PROJECT_ROOT, get_settings
from app.graph.client import GraphClient, GraphQueryError, GraphUnavailableError
from app.graph.queries import GraphQueries, catalog
from app.ingestion.loader import ScenarioNotFound, ingest, list_scenarios, load_scenario
from app.investigation.engine import InvestigationEngine, SeedNotFound
from app.models.schemas import EventIngestRequest, InvestigationRequest
from app.reporting.report import json_report, markdown_report

logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
log = logging.getLogger("incidentzero.api")

app = FastAPI(title="IncidentZero", version="0.1.0",
              description="Graph-native forensic investigation over synthetic event logs, backed by FalkorDB.")
client = GraphClient()
FRONTEND = PROJECT_ROOT / "frontend" / "index.html"


@app.exception_handler(GraphUnavailableError)
async def _graph_down(_: Request, exc: GraphUnavailableError):
    log.error("graph unavailable: %s", exc)
    return JSONResponse(status_code=503, content={"error": "graph_unavailable", "detail": str(exc),
                                                  "note": "No investigation was performed; IncidentZero has no "
                                                          "non-graph fallback."})


@app.exception_handler(GraphQueryError)
async def _graph_err(_: Request, exc: GraphQueryError):
    log.error("graph query error: %s", exc)
    return JSONResponse(status_code=502, content={"error": "graph_query_failed", "detail": str(exc)[:500]})


@app.middleware("http")
async def _timing(request: Request, call_next):
    t = time.time()
    resp = await call_next(request)
    log.info("%s %s -> %s in %dms", request.method, request.url.path, resp.status_code, (time.time() - t) * 1000)
    return resp


def _scenario_ids() -> set[str]:
    return {s["scenario_id"] for s in list_scenarios()}


def _known_graph(scenario_id: str) -> None:
    if client.graph_name(scenario_id) not in client.list_graphs():
        raise HTTPException(404, f"scenario {scenario_id!r} is not loaded; POST /api/scenarios/{scenario_id}/load")


def _load_investigation(investigation_id: str, scenario_id: str | None) -> dict[str, Any]:
    if not investigation_id.startswith("inv-") or len(investigation_id) > 40:
        raise HTTPException(400, "invalid investigation id")
    graphs = client.list_graphs()
    prefix = client.settings.graph_prefix
    candidates = [scenario_id] if scenario_id else [g[len(prefix):] for g in graphs if g.startswith(prefix)]
    for sid in candidates:
        if client.graph_name(sid) not in graphs:
            continue
        rows = client.rows(sid, "MATCH (i:Investigation {investigation_id: $id}) RETURN i.result_json AS j",
                           {"id": investigation_id})
        if rows:
            return json.loads(rows[0]["j"])
    raise HTTPException(404, f"investigation {investigation_id!r} not found")


@app.get("/health")
def health() -> dict[str, Any]:
    try:
        info = client.ping()
        mods = [m for m in info["modules"] if m.get("name") == "graph"]
        return {"status": "ok", "falkordb": "reachable", "graph_module": mods[0] if mods else None}
    except GraphUnavailableError as exc:
        return JSONResponse(status_code=503, content={"status": "degraded", "falkordb": "unreachable",
                                                      "detail": str(exc)})


@app.get("/api/scenarios")
def scenarios() -> list[dict[str, Any]]:
    try:
        loaded = set(client.list_graphs())
    except GraphUnavailableError:
        loaded = None
    out = []
    for s in list_scenarios():
        s = dict(s)
        s["loaded"] = None if loaded is None else client.graph_name(s["scenario_id"]) in loaded
        out.append(s)
    return out


@app.post("/api/scenarios/{scenario_id}/load")
def load(scenario_id: str, reset: bool = Query(True)) -> dict[str, Any]:
    try:
        res = load_scenario(client, scenario_id, reset=reset)
    except ScenarioNotFound as exc:
        raise HTTPException(404, str(exc))
    return res.model_dump()


@app.post("/api/events/ingest")
def ingest_events(req: EventIngestRequest) -> dict[str, Any]:
    if req.scenario_id in _scenario_ids():
        raise HTTPException(409, "use POST /api/scenarios/{id}/load for bundled scenarios")
    try:
        res = ingest(client, req.scenario_id, req.events, req.hosts, req.identities)
    except ValueError as exc:
        raise HTTPException(413, str(exc))
    return res.model_dump()


@app.get("/api/events")
def events(scenario_id: str, event_type: str | None = None, host_id: str | None = None,
           skip: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    _known_graph(scenario_id)
    gq = GraphQueries(client, scenario_id)
    rows = gq.run("events_list", event_type=event_type, host_id=host_id, skip=skip, limit=limit)
    for r in rows:
        r["raw_fields"] = json.loads(r.pop("raw_fields_json") or "{}")
    counts = gq.run("counts")
    rels = gq.run("rel_counts")
    return {"scenario_id": scenario_id, "events": rows, "node_counts": counts, "relationship_counts": rels}


@app.get("/api/events/{event_id}")
def event_detail(event_id: str, scenario_id: str) -> dict[str, Any]:
    """Provenance drill-down for one event: source record, raw fields and its graph relationships."""
    _known_graph(scenario_id)
    gq = GraphQueries(client, scenario_id)
    rows = gq.run("event_by_id", event_id=event_id)
    if not rows:
        raise HTTPException(404, f"event {event_id!r} not found")
    ev = rows[0]
    ev["raw_fields"] = json.loads(ev.pop("raw_fields_json") or "{}")
    ev["relationships"] = gq.run("subgraph_for_events", ids=[event_id])
    return ev


@app.get("/api/investigations")
def investigations(scenario_id: str | None = None) -> list[dict[str, Any]]:
    graphs = client.list_graphs()
    prefix = client.settings.graph_prefix
    sids = [scenario_id] if scenario_id else [g[len(prefix):] for g in graphs if g.startswith(prefix)]
    out = []
    for sid in sids:
        if client.graph_name(sid) not in graphs:
            continue
        out += [dict(r, scenario_id=sid) for r in client.rows(
            sid, "MATCH (i:Investigation) RETURN i.investigation_id AS investigation_id, i.name AS name, "
                 "i.created_at AS created_at, i.assessment AS assessment ORDER BY created_at DESC LIMIT 100")]
    return out


@app.post("/api/investigations", status_code=201)
def create_investigation(req: InvestigationRequest) -> dict[str, Any]:
    _known_graph(req.scenario_id)
    try:
        return InvestigationEngine(client).investigate(req)
    except SeedNotFound as exc:
        raise HTTPException(404, str(exc))


@app.get("/api/investigations/{investigation_id}")
def get_investigation(investigation_id: str, scenario_id: str | None = None) -> dict[str, Any]:
    return _load_investigation(investigation_id, scenario_id)


@app.get("/api/investigations/{investigation_id}/timeline")
def get_timeline(investigation_id: str, scenario_id: str | None = None) -> dict[str, Any]:
    r = _load_investigation(investigation_id, scenario_id)
    return {"investigation_id": investigation_id, "timeline": r["timeline"], "gaps": r["timeline_gaps"]}


@app.get("/api/investigations/{investigation_id}/evidence")
def get_evidence(investigation_id: str, scenario_id: str | None = None) -> dict[str, Any]:
    r = _load_investigation(investigation_id, scenario_id)
    return {"investigation_id": investigation_id, "findings": r["findings"], "event_chains": r["event_chains"],
            "provenance": r["provenance"], "query_log": r["query_log"]}


@app.get("/api/investigations/{investigation_id}/hypotheses")
def get_hypotheses(investigation_id: str, scenario_id: str | None = None) -> dict[str, Any]:
    r = _load_investigation(investigation_id, scenario_id)
    gq = GraphQueries(client, r["scenario_id"])
    prov = {h["hypothesis_id"]: gq.run("hypothesis_provenance", hypothesis_id=h.get("graph_hypothesis_id", ""))
            for h in r["hypotheses"]}
    return {"investigation_id": investigation_id, "assessment": r["assessment"], "hypotheses": r["hypotheses"],
            "graph_provenance": prov}


@app.get("/api/investigations/{investigation_id}/graph")
def get_graph(investigation_id: str, scenario_id: str | None = None) -> dict[str, Any]:
    r = _load_investigation(investigation_id, scenario_id)
    gq = GraphQueries(client, r["scenario_id"])
    edges = gq.run("subgraph_for_events", ids=r["evidence_event_ids"])
    keys = sorted({e["dst"] for e in edges if e["dst_label"] == "Process"})
    pedges = gq.run("process_edges_for_keys", keys=keys) if keys else []
    nodes: dict[str, dict] = {}
    for e in edges:
        nodes.setdefault(e["src"], {"id": e["src"], "label": "Event"})
        nodes.setdefault(e["dst"], {"id": e["dst"], "label": e["dst_label"]})
    links = [{"source": e["src"], "target": e["dst"], "type": e["rel"], "classification": e["classification"]}
             for e in edges]
    for p in pedges:
        nodes.setdefault(p["child"], {"id": p["child"], "label": "Process"})
        nodes.setdefault(p["parent"], {"id": p["parent"], "label": "Process"})
        links.append({"source": p["child"], "target": p["parent"], "type": "PARENT_PROCESS",
                      "classification": p["classification"]})
    return {"investigation_id": investigation_id, "nodes": list(nodes.values()), "links": links,
            "queries": gq.log}


@app.post("/api/investigations/{investigation_id}/next-evidence")
def next_evidence(investigation_id: str, scenario_id: str | None = None,
                  body: dict[str, Any] | None = Body(default=None)) -> dict[str, Any]:
    r = _load_investigation(investigation_id, scenario_id)
    return {"investigation_id": investigation_id, "assessment": r["assessment"]["status"],
            "unknowns": r["unknowns"], "next_evidence": r["next_evidence"]}


@app.get("/api/investigations/{investigation_id}/report")
def report(investigation_id: str, format: str = Query("json", pattern="^(json|markdown)$"),
           scenario_id: str | None = None):
    r = _load_investigation(investigation_id, scenario_id)
    if format == "markdown":
        return PlainTextResponse(markdown_report(r), media_type="text/markdown")
    return json_report(r)


@app.get("/api/queries")
def queries() -> list[dict[str, str]]:
    return [{"name": q.name, "purpose": q.purpose, "cypher": q.cypher}
            for q in catalog(get_settings().max_hops).values()]


@app.get("/", include_in_schema=False)
def ui():
    if FRONTEND.is_file():
        return FileResponse(FRONTEND)
    raise HTTPException(404, "frontend not found")
