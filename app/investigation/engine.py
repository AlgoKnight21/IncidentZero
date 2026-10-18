"""Deterministic, inspectable investigation pipeline.

A. parse question/scope  B. retrieve seed + entities from FalkorDB  C. timeline  D. multi-hop chains
E. competing hypotheses  F. rule-based evaluation  G. next-best evidence  H. persist auditable result

Python orchestrates; every fact comes from a FalkorDB query recorded in `query_log`.
The engine never opens evaluator-only files (see app.config.assert_engine_readable).
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

from app.graph.client import GraphClient
from app.graph.queries import GraphQueries
from app.investigation import rules as R
from app.models.schemas import InvestigationRequest

EVENT_ID_RE = re.compile(r"\b[A-Z][A-Z0-9]*-\d{3,}\b")
HOST_RE = re.compile(r"\b(?:WS|SRV)-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")


class InvestigationError(RuntimeError):
    pass


class SeedNotFound(InvestigationError):
    pass


def investigation_id(req: InvestigationRequest, seed: str | None) -> str:
    raw = f"{req.scenario_id}|{seed}|{req.window_minutes}|{req.question.strip()}"
    return "inv-" + hashlib.sha1(raw.encode()).hexdigest()[:12]


class Builder:
    """Accumulates findings; every finding carries event ids and the rule/query that produced it."""

    def __init__(self):
        self.findings: list[dict[str, Any]] = []

    def add(self, kind: str, statement: str, event_ids: list[str], *, rule: str | None = None,
            query: str | None = None, **extra) -> dict:
        assert kind in ("observation", "inference", "contradiction", "unknown")
        f = {"finding_id": f"F{len(self.findings) + 1:03d}", "kind": kind, "statement": statement,
             "event_ids": sorted(set(event_ids)), "rule": rule, "query": query, **extra}
        self.findings.append(f)
        return f


class InvestigationEngine:
    def __init__(self, client: GraphClient):
        self.client = client

    # ------------------------------------------------------------------ A/B
    def _choose_seed(self, gq: GraphQueries, req: InvestigationRequest) -> tuple[str | None, str]:
        if req.seed_event_id:
            return req.seed_event_id, "explicit seed_event_id"
        ids = EVENT_ID_RE.findall(req.question or "")
        if ids:
            return ids[0], "event id named in question"
        alerts = gq.run("seed_candidates")
        if not alerts:
            return None, "no edr_alert events in graph"
        hosts = set(HOST_RE.findall(req.question or ""))
        scoped = [a for a in alerts if a["host_id"] in hosts] if hosts else []
        pool = scoped or alerts
        sev = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        pool.sort(key=lambda a: (-sev.get((a.get("severity") or "").lower(), 0), a["ts_epoch"], a["event_id"]))
        why = f"earliest highest-severity alert on host named in question {sorted(hosts)}" if scoped else \
            "earliest highest-severity alert in scenario"
        return pool[0]["event_id"], why

    # ------------------------------------------------------------------ main
    def investigate(self, req: InvestigationRequest) -> dict[str, Any]:
        started = time.time()
        gq = GraphQueries(self.client, req.scenario_id)
        b = Builder()
        win = req.window_minutes * 60
        seed_id, seed_reason = self._choose_seed(gq, req)
        if seed_id is None:
            return self._empty_result(req, gq, seed_reason, started)
        seed_rows = gq.run("event_by_id", event_id=seed_id)
        if not seed_rows:
            raise SeedNotFound(f"seed event {seed_id!r} not found in graph for {req.scenario_id}")
        seed = seed_rows[0]
        host = seed["host_id"]
        t0 = seed["ts_epoch"]
        b.add("observation", f"Seed event {seed_id} ({seed['event_type']}) on {host} at {seed['timestamp']}: "
                             f"{seed['summary']}", [seed_id], query="event_by_id")

        # ---- D1 process lineage (multi-hop up) --------------------------------------------
        lineage = gq.run("process_lineage", event_id=seed_id)
        missing_parents = []
        for row in lineage:
            if row["creation_event_id"]:
                b.add("observation", f"Process {row['process_key']} ({R.basename(row['executable'])}) created at "
                                     f"{row['creation_ts']} (lineage depth {row['depth']})",
                      [row["creation_event_id"]], query="process_lineage")
            elif row["depth"] == 1:
                # only the seed process's immediate parent matters for attribution (rule M3)
                missing_parents.append(row)
        # ---- D2 process tree activity (multi-hop down) ------------------------------------
        tree = gq.run("process_tree_activity", event_id=seed_id)
        tree_ids = sorted({r["event_id"] for r in tree})
        for r in tree:
            detail = r["summary"]
            if r["endpoint"]:
                detail += f" [endpoint {r['endpoint']}:{r['port']}]"
            if r["file"]:
                detail += f" [file {r['file']}]"
            b.add("observation", f"{r['timestamp']} {r['event_type']} by {r['process_key']} "
                                 f"({R.basename(r['executable']) or 'executable unknown'}): {detail}",
                  [r["event_id"]], query="process_tree_activity")
        # ---- context before seed (temporal only) ------------------------------------------
        context = gq.run("host_actor_context", event_id=seed_id, before_s=min(win, 600))
        context_ids = [c["event_id"] for c in context]
        for c in context:
            b.add("observation", f"Context (temporal only, not causal): {c['timestamp']} {c['summary']}",
                  [c["event_id"]], query="host_actor_context", temporal_only=True)

        # ---- endpoints -------------------------------------------------------------------
        endpoints = sorted({r["endpoint"] for r in tree if r["endpoint"]})
        prevalence: dict[str, list[dict]] = {}
        for ip in endpoints:
            prevalence[ip] = gq.run("endpoint_prevalence", ip=ip)

        # ---- D3 cross-host pivot ---------------------------------------------------------
        auths = gq.run("cross_host_auth", host_id=host, t_from=t0, t_to=t0 + win)
        cross: list[dict] = []
        for a in auths:
            baseline = gq.run("identity_baseline", account=a["account"], before=t0)
            follow = gq.run("identity_followon", account=a["account"], host_id=a["target_host"],
                            t_from=a["ts_epoch"], t_to=a["ts_epoch"] + win) if a["result"] == "success" else []
            cross.append({"auth": a, "baseline": baseline, "followon": follow})
            b.add("observation", f"{a['timestamp']} authentication {a['result']} for {a['account']} "
                                 f"({a['account_type']}) on {a['target_host']}", [a["event_id"]],
                  query="cross_host_auth")
            b.add("inference", f"Authentication {a['event_id']} originated from {host} "
                               f"(rule R1: source address matches inventory). Caveat: {a['caveat']}",
                  [a["event_id"]], rule="R1", query="cross_host_auth", classification=a["classification"])
        # evidence path explanation seed -> first cross-host auth
        paths = []
        for c in cross[:3]:
            try:
                p = gq.run("evidence_path", a=seed_id, b=c["auth"]["event_id"])
            except Exception as exc:  # keep investigation alive, but record the failure
                p = []
                b.add("unknown", f"Evidence path query failed: {exc}", [seed_id], query="evidence_path")
            if p:
                paths.append({"from": seed_id, "to": c["auth"]["event_id"], **p[0]})

        # ---- change records / telemetry -------------------------------------------------
        changes = gq.run("change_records_at", ts=t0)
        sensor = gq.run("sensor_status", host_id=host)
        coverage = gq.run("host_telemetry_coverage", host_id=host)
        auth_roles = gq.run("auth_by_host_role")

        hyps, unknowns, next_steps = self._evaluate(b, seed, lineage, missing_parents, tree, prevalence, cross,
                                                    changes, sensor, auth_roles, gq, t0, win)

        # ---- C timeline over the evidence set --------------------------------------------
        evidence_ids = {seed_id, *tree_ids, *context_ids}
        for c in cross:
            evidence_ids.add(c["auth"]["event_id"])
            evidence_ids.update(f["event_id"] for f in c["followon"])
        for h in hyps:
            for item in h["supporting"] + h["contradicting"]:
                evidence_ids.update(item["event_ids"])
        for u in unknowns:
            evidence_ids.update(u["event_ids"])
        for f in b.findings:  # anything cited in a finding is part of the evidence set and timeline
            evidence_ids.update(f["event_ids"])
        timeline = gq.run("timeline_by_ids", ids=sorted(evidence_ids))
        gaps = self._timeline_gaps(timeline, sensor)

        # ---- provenance validation (graph round trip) ------------------------------------
        all_ref = sorted({i for f in b.findings for i in f["event_ids"]} | evidence_ids)
        existing = set(gq.run("existing_event_ids", ids=all_ref)[0]["ids"]) if all_ref else set()
        unsupported = [f["finding_id"] for f in b.findings
                       if f["kind"] in ("observation", "inference", "contradiction")
                       and (not f["event_ids"] or not set(f["event_ids"]) <= existing)]
        factual = [f for f in b.findings if f["kind"] in ("observation", "inference", "contradiction")]
        coverage_ratio = (len(factual) - len(unsupported)) / len(factual) if factual else 1.0

        assessment = self._assess(hyps, unknowns)
        inv_id = investigation_id(req, seed_id)
        result = {
            "investigation_id": inv_id,
            "scenario_id": req.scenario_id,
            "question": req.question,
            "created_at": int(started),
            "scope": {"seed_event_id": seed_id, "seed_reason": seed_reason, "seed_host": host,
                      "window_minutes": req.window_minutes, "t_from": t0 - min(win, 600), "t_to": t0 + win},
            "assessment": assessment,
            "hypotheses": hyps,
            "findings": b.findings,
            "unknowns": unknowns,
            "next_evidence": next_steps,
            "timeline": timeline,
            "timeline_gaps": gaps,
            "event_chains": {"process_lineage": lineage, "process_tree_activity": tree,
                             "cross_host": cross, "evidence_paths": paths},
            "context": {"change_records": changes, "endpoint_prevalence": prevalence,
                        "telemetry_coverage": coverage, "sensor_status": sensor, "auth_by_host_role": auth_roles},
            "evidence_event_ids": sorted(evidence_ids),
            "provenance": {"factual_findings": len(factual), "unsupported_finding_ids": unsupported,
                           "coverage": round(coverage_ratio, 4), "referenced_event_ids_missing_from_graph":
                               sorted(set(all_ref) - existing)},
            "query_log": gq.log,
            "rules": R.RULES,
            "disclaimer": "Confidence levels are qualitative and rule-based, not calibrated probabilities. "
                          "Temporal proximity is never treated as proof of causation.",
            "duration_ms": int((time.time() - started) * 1000),
        }
        self.persist(req.scenario_id, result)
        return result

    # ------------------------------------------------------------------ E/F
    def _evaluate(self, b: Builder, seed, lineage, missing_parents, tree, prevalence, cross, changes, sensor,
                  auth_roles, gq, t0, win):
        host = seed["host_id"]
        sup_c: list[dict] = []   # supports compromise
        con_c: list[dict] = []   # contradicts compromise
        sup_b: list[dict] = []   # supports benign
        con_b: list[dict] = []   # contradicts benign

        def item(rule, text, ids, weight=None):
            return {"rule": rule, "rationale": text, "event_ids": sorted(set(ids)),
                    "weight": weight if weight is not None else R.RULES[rule].get("weight", 1)}

        # C1 / X5 lineage
        execs = [(r, R.basename(r["executable"])) for r in lineage]
        interp = [r for r, n in execs if n in R.SCRIPT_INTERPRETERS]
        office = [r for r, n in execs if n in R.OFFICE_APPS]
        if interp and office and office[0]["depth"] > min(r["depth"] for r in interp):
            ids = [r["creation_event_id"] for r in interp + office if r["creation_event_id"]]
            it = item("C1", f"{R.basename(office[0]['executable'])} is an ancestor of "
                            f"{R.basename(interp[0]['executable'])} on {host}", ids)
            sup_c.append(it)
            con_b.append(it)
            b.add("inference", it["rationale"] + " (rule C1)", ids, rule="C1", query="process_lineage")
        admin_anc = [r for r in lineage if r["depth"] > 0 and R.is_admin_tool(r["executable"]) and r["signed"]]
        if interp and admin_anc and not office:
            ids = [r["creation_event_id"] for r in interp + admin_anc if r["creation_event_id"]]
            it = item("X5", f"script interpreter launched by signed admin tool "
                            f"{R.basename(admin_anc[0]['executable'])}", ids)
            con_c.append(it)
            sup_b.append(it)
            b.add("contradiction", it["rationale"] + " (rule X5, contradicts compromise)", ids, rule="X5",
                  query="process_lineage")
        # C7 obfuscation
        for r in lineage:
            if r["creation_event_id"] and r["depth"] == 0:
                cmd_rows = gq.run("event_by_id", event_id=r["creation_event_id"])
                raw = json.loads(cmd_rows[0]["raw_fields_json"] or "{}") if cmd_rows else {}
                if R.has_obfuscation(raw.get("command_line")):
                    it = item("C7", "seed process command line contains hidden-window/encoded-command flags",
                              [r["creation_event_id"]])
                    sup_c.append(it)
                    b.add("inference", it["rationale"] + " (rule C7)", it["event_ids"], rule="C7", query="event_by_id")
        # C2 executable drop
        drops = [r for r in tree if r["file"] and r["file"].rsplit(".", 1)[-1].lower() in R.EXECUTABLE_FILE_TYPES]
        if drops:
            it = item("C2", "process tree wrote " + ", ".join(sorted({d["file"] for d in drops})),
                      [d["event_id"] for d in drops])
            sup_c.append(it)
            con_b.append(it)
            b.add("inference", it["rationale"] + " (rule C2)", it["event_ids"], rule="C2", query="process_tree_activity")
        # C3 / X2 endpoints
        for ip, rows in prevalence.items():
            owners = [o for r in rows for o in (r["owners"] or [])]
            if not R.is_external(ip, owners):
                continue
            own = [r for r in rows if r["host_id"] == host]
            others = [r for r in rows if r["host_id"] != host]
            ids_own = [e for r in own for e in r["event_ids"]]
            it = item("C3", f"process tree on {host} connected to external endpoint {ip}",
                      [r["event_id"] for r in tree if r["endpoint"] == ip])
            sup_c.append(it)
            b.add("inference", it["rationale"] + " (rule C3)", it["event_ids"], rule="C3", query="endpoint_prevalence")
            unattributed = sorted(set(ids_own) - set(it["event_ids"]))
            if unattributed:
                b.add("observation", f"{host} made {len(unattributed)} further connection(s) to {ip} that are not "
                                     f"attributed to any process (no process_id in the record)", unattributed,
                      query="endpoint_prevalence")
            if others:
                oids = [e for r in others for e in r["event_ids"]]
                it2 = item("X2", f"{ip} was also contacted by {', '.join(r['host_id'] for r in others)}", oids)
                con_c.append(it2)
                sup_b.append(it2)
                b.add("contradiction", it2["rationale"] + " (rule X2; weakens 'unique malicious endpoint')", oids,
                      rule="X2", query="endpoint_prevalence")
            elif ids_own:
                b.add("inference", f"No other host contacted {ip} in the dataset", ids_own, rule="C3",
                      query="endpoint_prevalence")
        # X3 alert disposition
        if seed["event_type"] == "edr_alert":
            raw = json.loads(gq.run("event_by_id", event_id=seed["event_id"])[0]["raw_fields_json"] or "{}")
            if (raw.get("severity") or "").lower() in ("low", "medium") and raw.get("action") == "allowed":
                it = item("X3", f"alert severity {raw.get('severity')} and action '{raw.get('action')}'",
                          [seed["event_id"]])
                con_c.append(it)
                b.add("contradiction", it["rationale"] + " (rule X3, weak)", it["event_ids"], rule="X3",
                      query="event_by_id")
        # X1 change records
        covering = [c for c in changes if host in (c["covered_hosts"] or [])]
        for c in covering:
            it = item("X1", f"approved change {c['change_id']} covers {host} at the seed time", [c["event_id"]])
            con_c.append(it)
            sup_b.append(it)
            b.add("contradiction", it["rationale"] + " (rule X1)", it["event_ids"], rule="X1", query="change_records_at")
        for c in changes:
            if c not in covering:
                b.add("observation", f"Change {c['change_id']} was active at the seed time but covers only "
                                     f"{', '.join(c['covered_hosts'] or [])}, not {host}", [c["event_id"]],
                      query="change_records_at", considered_and_rejected=True)
        # C4/C5/C6/X4 cross-host identity use
        by_acct: dict[str, list[dict]] = {}
        for c in cross:
            by_acct.setdefault(c["auth"]["account"], []).append(c)
        for acct, items in by_acct.items():
            baseline = items[0]["baseline"]
            origins = {r["origin"] for r in baseline}
            succ = [c for c in items if c["auth"]["result"] == "success"]
            fail = [c for c in items if c["auth"]["result"] == "failure"]
            auth_ids = [c["auth"]["event_id"] for c in items]
            base_ids = [e for r in baseline for e in r["event_ids"]]
            if baseline and host not in origins:
                it = item("C4", f"{acct} authenticated from {host}; prior baseline origins: {sorted(origins)}",
                          auth_ids + base_ids)
                sup_c.append(it)
                con_b.append(it)
                b.add("inference", it["rationale"] + " (rule C4)", it["event_ids"], rule="C4", query="identity_baseline")
                if fail and succ and min(f["auth"]["ts_epoch"] for f in fail) < max(s["auth"]["ts_epoch"] for s in succ):
                    it5 = item("C5", f"failed then successful authentication for {acct} from {host}", auth_ids)
                    sup_c.append(it5)
                    b.add("inference", it5["rationale"] + " (rule C5)", auth_ids, rule="C5", query="cross_host_auth")
                fo = [f for s in succ for f in s["followon"] if f["file"]]
                if fo:
                    it6 = item("C6", f"{acct} then accessed " + ", ".join(sorted({f['file'] for f in fo})),
                               [f["event_id"] for f in fo])
                    sup_c.append(it6)
                    b.add("inference", it6["rationale"] + " (rule C6)", it6["event_ids"], rule="C6",
                          query="identity_followon")
            elif baseline and host in origins:
                it = item("X4", f"{acct} has previously authenticated from {host} "
                                f"({sum(r['n'] for r in baseline if r['origin'] == host)} prior events)",
                          auth_ids + [e for r in baseline if r["origin"] == host for e in r["event_ids"]])
                con_c.append(it)
                sup_b.append(it)
                b.add("contradiction", it["rationale"] + " (rule X4)", it["event_ids"], rule="X4",
                      query="identity_baseline")
            else:
                b.add("unknown", f"No prior authentication baseline for {acct}; cannot judge whether origin "
                                 f"{host} is unusual", auth_ids, rule="C4", query="identity_baseline")

        # ---- unknowns / missing telemetry -----------------------------------------------
        unknowns: list[dict] = []
        gaps = self._sensor_gaps(sensor)
        relevant_ts = [t0] + [c["auth"]["ts_epoch"] for c in cross]
        for g in gaps:
            end = g["end"] if g["end"] is not None else float("inf")
            overlaps = [t for t in relevant_ts if g["start"] <= t <= end] or \
                       (g["start"] <= t0 + win and end >= t0)
            if overlaps:
                ids = [x for x in (g["offline_event"], g["online_event"]) if x]
                u = {"key": f"process_telemetry_gap:{host}", "rule": "M1",
                     "statement": f"EDR sensor on {host} offline from {g['start_iso']} to "
                                  f"{g['end_iso'] or 'end of data'}; process activity in this period is unobservable",
                     "event_ids": ids,
                     "affects": "Cannot attribute cross-host authentications to a process on the seed host"
                                if cross else "Cannot see follow-on process activity"}
                unknowns.append(u)
        if missing_parents:
            mp = missing_parents[0]
            u = {"key": f"missing_parent_process:{host}", "rule": "M3",
                 "statement": f"Parent process {mp['process_key']} has no process-creation record",
                 "event_ids": [r["creation_event_id"] for r in lineage if r["creation_event_id"]][:1],
                 "affects": "Cannot determine what launched the seed process"}
            unknowns.append(u)
        roles = {r["role"]: r["n"] for r in auth_roles}
        if not roles:
            unknowns.append({"key": "no_authentication_logs", "rule": "M4",
                             "statement": "No authentication telemetry exists in this dataset",
                             "event_ids": [], "affects": "Cannot determine whether any credential was used"})
        elif "domain_controller" not in roles and cross:
            unknowns.append({"key": "no_domain_controller_auth_logs", "rule": "M2",
                             "statement": "No domain-controller authentication logs are present",
                             "event_ids": [], "affects": "Cannot see ticket/credential requests for "
                                                        + ", ".join(sorted(by_acct))})
        for u in unknowns:
            b.add("unknown", u["statement"] + f" (rule {u['rule']})", u["event_ids"], rule=u["rule"],
                  query="sensor_status" if u["rule"] == "M1" else "auth_by_host_role")

        # ---- hypotheses -----------------------------------------------------------------
        targets = sorted({c["auth"]["target_host"] for c in cross if c["auth"]["result"] == "success"})
        accts = sorted(by_acct)
        desc_c = f"Malicious execution on {host}" + (
            f" followed by use of {', '.join(accts)} against {', '.join(targets)}" if targets else "")
        hyps = [
            self._hyp("H1", "compromise", desc_c, sup_c, con_c, unknowns),
            self._hyp("H2", "benign_admin_or_maintenance",
                      f"Activity on {host} is authorised administrative or maintenance activity",
                      sup_b, con_b, unknowns),
        ]
        next_steps = self._next_evidence(unknowns, cross, host, t0, win)
        return hyps, unknowns, next_steps

    @staticmethod
    def _hyp(hid, kind, desc, sup, con, unknowns):
        s = sum(i["weight"] for i in sup)
        c = sum(i["weight"] for i in con)
        missing = [u["key"] for u in unknowns]
        if s >= 4 and c <= s / 2:
            conf = "moderate" if missing else "high"
        elif s >= 2 and c < s:
            conf = "low-to-moderate"
        else:
            conf = "low"
        rationale = (f"Support weight {s} from rules {[i['rule'] for i in sup]}; contradiction weight {c} from "
                     f"{[i['rule'] for i in con]}; {len(missing)} missing-evidence item(s). Weights are ordinal "
                     f"heuristics, not probabilities.")
        if missing and conf == "high":
            conf = "moderate"
        assumptions = ["Static inventory IP-to-host mapping (rule R1) was valid at event time",
                       "Event timestamps from different sources are on a synchronised UTC clock"]
        return {"hypothesis_id": hid, "kind": kind, "description": desc, "supporting": sup, "contradicting": con,
                "missing_evidence": missing, "assumptions": assumptions, "support_score": s,
                "contradiction_score": c, "confidence": conf, "confidence_rationale": rationale}

    @staticmethod
    def _assess(hyps, unknowns):
        net = {h["hypothesis_id"]: h["support_score"] - h["contradiction_score"] for h in hyps}
        best = max(hyps, key=lambda h: (net[h["hypothesis_id"]], h["hypothesis_id"] == "H2"))
        other = [h for h in hyps if h is not best]
        margin = net[best["hypothesis_id"]] - max(net[h["hypothesis_id"]] for h in other)
        if best["support_score"] < 4 and len(unknowns) >= 2 or margin < 2 or best["support_score"] < 2:
            status = "inconclusive"
            leading = None
            statement = ("Insufficient evidence to favour one explanation. "
                         f"Net scores: {net}. Missing: {[u['key'] for u in unknowns]}")
        else:
            status = "compromise_likely" if best["kind"] == "compromise" else "benign_likely"
            leading = best["hypothesis_id"]
            statement = (f"{best['hypothesis_id']} ({best['kind']}) is favoured with {best['confidence']} confidence; "
                         f"not confirmed. Net scores: {net}.")
        for h in hyps:
            h["status"] = ("favoured" if h["hypothesis_id"] == leading else
                           "not_favoured" if leading else "unresolved")
        return {"status": status, "leading_hypothesis": leading, "statement": statement, "net_scores": net,
                "multiple_hypotheses_meaningful": all(h["support_score"] > 0 for h in hyps)}

    @staticmethod
    def _sensor_gaps(sensor):
        gaps = []
        open_g = None
        for s in sensor:
            if s["status"] == "offline" and open_g is None:
                open_g = {"start": s["ts_epoch"], "start_iso": s["timestamp"], "offline_event": s["event_id"],
                          "end": None, "end_iso": None, "online_event": None}
            elif s["status"] == "online" and open_g is not None:
                open_g.update(end=s["ts_epoch"], end_iso=s["timestamp"], online_event=s["event_id"])
                gaps.append(open_g)
                open_g = None
        if open_g:
            gaps.append(open_g)
        return gaps

    def _timeline_gaps(self, timeline, sensor):
        out = [{"type": "sensor_offline", **g} for g in self._sensor_gaps(sensor)]
        for a, b2 in zip(timeline, timeline[1:]):
            if b2["ts_epoch"] - a["ts_epoch"] > 1800:
                out.append({"type": "evidence_gap", "after_event": a["event_id"], "before_event": b2["event_id"],
                            "seconds": b2["ts_epoch"] - a["ts_epoch"]})
        return out

    @staticmethod
    def _next_evidence(unknowns, cross, host, t0, win):
        from datetime import datetime, timezone

        def iso(t):
            return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        steps = []
        accts = sorted({c["auth"]["account"] for c in cross})
        for u in unknowns:
            if u["rule"] == "M1":
                steps.append({"priority": 1, "key": u["key"], "collect": f"EDR process-creation backlog or local "
                              f"process audit log (e.g. OS process-creation events) from {host} for the offline period",
                              "why": "Would show whether a process on the seed host initiated the "
                                     f"{', '.join(accts) or 'observed'} activity; distinguishes credential misuse "
                                     "from a scheduled/legitimate job.", "event_ids": u["event_ids"]})
            elif u["rule"] == "M2":
                steps.append({"priority": 2, "key": u["key"], "collect": f"Domain-controller authentication / ticket "
                              f"logs for {', '.join(accts)} between {iso(t0)} and {iso(t0 + win)}",
                              "why": "Would show where credential requests originated and whether the account was "
                                     "used elsewhere; tests the compromise hypothesis independently of host logs.",
                              "event_ids": u["event_ids"]})
            elif u["rule"] == "M3":
                steps.append({"priority": 1, "key": u["key"], "collect": f"Recover the parent process of the seed "
                              f"process on {host} (EDR backlog, prefetch/shimcache-style artefacts, memory image)",
                              "why": "A document application parent would support compromise; a management agent "
                                     "parent would support benign administration.", "event_ids": u["event_ids"]})
            elif u["rule"] == "M4":
                steps.append({"priority": 1, "key": u["key"], "collect": "Authentication logs from the hosts the "
                              "seed host connected to (e.g. SSH/auth logs on internal servers)",
                              "why": "Determines whether any connection resulted in a successful logon.",
                              "event_ids": u["event_ids"]})
        if cross:
            steps.append({"priority": 3, "key": "verify_R1_mapping", "collect": f"DHCP/IPAM lease records for the "
                          f"address of {host} at the authentication times",
                          "why": "Rule R1 relies on the static inventory mapping; a lease record verifies the "
                                 "cross-host link.", "event_ids": [c["auth"]["event_id"] for c in cross]})
        steps.sort(key=lambda s: (s["priority"], s["key"]))
        return steps

    def _empty_result(self, req, gq, reason, started):
        return {"investigation_id": investigation_id(req, None), "scenario_id": req.scenario_id,
                "question": req.question, "created_at": int(started),
                "scope": {"seed_event_id": None, "seed_reason": reason},
                "assessment": {"status": "inconclusive", "leading_hypothesis": None,
                               "statement": f"No investigation seed available ({reason}). Insufficient evidence "
                                            "for multiple meaningful explanations.",
                               "multiple_hypotheses_meaningful": False},
                "hypotheses": [], "findings": [], "unknowns": [], "next_evidence": [], "timeline": [],
                "timeline_gaps": [], "event_chains": {}, "context": {}, "evidence_event_ids": [],
                "provenance": {"factual_findings": 0, "unsupported_finding_ids": [], "coverage": 1.0,
                               "referenced_event_ids_missing_from_graph": []},
                "query_log": gq.log, "rules": R.RULES, "duration_ms": int((time.time() - started) * 1000)}

    # ------------------------------------------------------------------ H persist
    def persist(self, scenario_id: str, result: dict[str, Any]) -> None:
        c = self.client
        inv = result["investigation_id"]
        for h in result["hypotheses"]:  # assign before the result JSON is stored
            h["graph_hypothesis_id"] = f"{inv}:{h['hypothesis_id']}"
        c.run(scenario_id, """MERGE (i:Investigation {investigation_id: $id})
SET i.name = $name, i.scenario_id = $scenario_id, i.created_at = $created, i.result_json = $json,
    i.assessment = $status""", {"id": inv, "name": result["question"][:200] or inv, "scenario_id": scenario_id,
                                "created": result["created_at"], "json": json.dumps(result, default=str),
                                "status": result["assessment"]["status"]}, read_only=False)
        c.run(scenario_id, """MATCH (i:Investigation {investigation_id: $id})
UNWIND $ids AS eid MATCH (e:Event {event_id: eid}) MERGE (i)-[r:HAS_EVENT]->(e)
ON CREATE SET r.classification = 'investigation_scope'""",
              {"id": inv, "ids": result["evidence_event_ids"]}, read_only=False)
        for h in result["hypotheses"]:
            hid = f"{inv}:{h['hypothesis_id']}"
            c.run(scenario_id, """MATCH (i:Investigation {investigation_id: $inv})
MERGE (h:Hypothesis {hypothesis_id: $hid})
SET h.description = $desc, h.kind = $kind, h.status = $status, h.confidence = $conf,
    h.confidence_rationale = $rat
MERGE (i)-[hh:HAS_HYPOTHESIS]->(h)
ON CREATE SET hh.classification = 'investigation_scope'
WITH h MATCH (seed:Event {event_id: $seed}) MERGE (h)-[d:DERIVED_FROM]->(seed)
ON CREATE SET d.classification = 'inferred', d.derivation = 'investigation_seed'""",
                  {"inv": inv, "hid": hid, "desc": h["description"], "kind": h["kind"], "status": h["status"],
                   "conf": h["confidence"], "rat": h["confidence_rationale"],
                   "seed": result["scope"]["seed_event_id"]}, read_only=False)
            for rel, items in (("SUPPORTS", h["supporting"]), ("CONTRADICTS", h["contradicting"])):
                rows = [{"eid": e, "rule": it["rule"], "rationale": it["rationale"]}
                        for it in items for e in it["event_ids"]]
                if rows:
                    c.run(scenario_id, f"""MATCH (h:Hypothesis {{hypothesis_id: $hid}})
UNWIND $rows AS r MATCH (e:Event {{event_id: r.eid}})
MERGE (e)-[x:{rel} {{rule: r.rule}}]->(h)
ON CREATE SET x.rationale = r.rationale, x.classification = 'inferred'""", {"hid": hid, "rows": rows},
                          read_only=False)
