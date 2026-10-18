"""Structured JSON and Markdown reports built only from a stored investigation result."""
from __future__ import annotations

from typing import Any

KIND_LABEL = {"observation": "OBSERVED", "inference": "INFERRED", "contradiction": "CONTRADICTS",
              "unknown": "UNKNOWN"}


def json_report(result: dict[str, Any]) -> dict[str, Any]:
    keep = ("investigation_id", "scenario_id", "question", "created_at", "scope", "assessment", "hypotheses",
            "findings", "unknowns", "next_evidence", "timeline", "timeline_gaps", "evidence_event_ids",
            "provenance", "query_log", "rules", "disclaimer")
    rep = {k: result.get(k) for k in keep}
    rep["report_format"] = "incidentzero.report.v1"
    rep["synthetic_data_notice"] = "All events are synthetic and fictional."
    return rep


def _ids(ids: list[str]) -> str:
    return ", ".join(f"`{i}`" for i in ids) if ids else "_(no event reference)_"


def markdown_report(result: dict[str, Any]) -> str:
    a = result["assessment"]
    s = result["scope"]
    out: list[str] = []
    out.append(f"# IncidentZero investigation report — {result['investigation_id']}")
    out.append("")
    out.append(f"*Scenario:* `{result['scenario_id']}` (synthetic data)  ")
    out.append(f"*Question:* {result['question'] or '(none)'}  ")
    out.append(f"*Seed event:* `{s.get('seed_event_id')}` — {s.get('seed_reason')}")
    out.append("")
    out.append("## Assessment")
    out.append(f"**{a['status']}** — {a['statement']}")
    out.append("")
    out.append("> " + result.get("disclaimer", ""))
    out.append("")
    out.append("## Competing hypotheses")
    for h in result["hypotheses"]:
        out.append(f"### {h['hypothesis_id']} — {h['kind']} ({h['status']}, confidence: {h['confidence']})")
        out.append(h["description"])
        out.append("")
        out.append(f"*Confidence rationale:* {h['confidence_rationale']}")
        out.append("")
        out.append("| Relation | Rule | Rationale | Evidence |")
        out.append("|---|---|---|---|")
        for it in h["supporting"]:
            out.append(f"| supports | {it['rule']} | {it['rationale']} | {_ids(it['event_ids'])} |")
        for it in h["contradicting"]:
            out.append(f"| contradicts | {it['rule']} | {it['rationale']} | {_ids(it['event_ids'])} |")
        if not h["supporting"] and not h["contradicting"]:
            out.append("| — | — | no evidence retrieved for this hypothesis | — |")
        out.append("")
        out.append("*Missing evidence:* " + (", ".join(h["missing_evidence"]) or "none identified"))
        out.append("")
        out.append("*Assumptions:* " + "; ".join(h["assumptions"]))
        out.append("")
    out.append("## Findings")
    out.append("| ID | Type | Statement | Events | Rule / query |")
    out.append("|---|---|---|---|---|")
    for f in result["findings"]:
        out.append(f"| {f['finding_id']} | {KIND_LABEL[f['kind']]} | {f['statement'].replace('|', '/')} | "
                   f"{_ids(f['event_ids'])} | {f.get('rule') or ''} {f.get('query') or ''} |")
    out.append("")
    out.append("## Unknowns and missing telemetry")
    for u in result["unknowns"] or []:
        out.append(f"- **{u['key']}** ({u['rule']}): {u['statement']}. Impact: {u['affects']}. "
                   f"Evidence: {_ids(u['event_ids'])}")
    if not result["unknowns"]:
        out.append("- none identified")
    out.append("")
    out.append("## Recommended next evidence")
    for i, n in enumerate(result["next_evidence"], 1):
        out.append(f"{i}. **{n['collect']}** — {n['why']} (addresses `{n['key']}`)")
    out.append("")
    out.append("## Timeline (evidence set, UTC)")
    out.append("| Time | Event | Type | Host | Source record | Summary |")
    out.append("|---|---|---|---|---|---|")
    for e in result["timeline"]:
        out.append(f"| {e['timestamp']} | `{e['event_id']}` | {e['event_type']} | {e['host_id'] or ''} | "
                   f"{e['source_record_id']} | {(e['summary'] or '').replace('|', '/')} |")
    out.append("")
    if result.get("timeline_gaps"):
        out.append("**Gaps:** " + "; ".join(
            f"{g['type']} {g.get('start_iso') or g.get('after_event')} → {g.get('end_iso') or g.get('before_event')}"
            for g in result["timeline_gaps"]))
        out.append("")
    p = result["provenance"]
    out.append("## Provenance")
    out.append(f"- Factual findings: {p['factual_findings']}; linked to existing graph events: "
               f"{p['coverage'] * 100:.1f}%")
    out.append(f"- Unsupported findings: {p['unsupported_finding_ids'] or 'none'}")
    out.append(f"- Graph queries executed: {len(result['query_log'])}")
    out.append("")
    out.append("_All data in this report is synthetic. Temporal ordering does not imply causation._")
    return "\n".join(out) + "\n"
