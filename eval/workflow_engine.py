from __future__ import annotations

import hashlib
import json
import random
import re
import time
from typing import Any, Dict, List, Tuple

from contracts import validate_call
from controls import call_with_controls
from models import RunResult, ToolError


def hash_obj(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def compute_ecr(message: str) -> float:
    claim_lines = [ln for ln in message.splitlines() if ln.strip().startswith("- ")]
    if not claim_lines:
        return 0.0
    has_evidence = ("EvidenceRefs:" in message) and ("[" in message) and ("]" in message)
    return 1.0 if has_evidence else 0.0


def mock_tool_call(tool_name: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], float]:
    start = time.time()
    fi = payload.get("_fi", {})
    r = random.random()

    if tool_name == "logs.search":
        if r < float(fi.get("logs_search_down_rate", 0.0)):
            raise ToolError("UPSTREAM_DOWN", "logs backend unavailable")
        if r < float(fi.get("logs_search_down_rate", 0.0)) + float(fi.get("logs_search_timeout_rate", 0.0)):
            time.sleep(0.15)
            raise ToolError("UPSTREAM_TIMEOUT", "logs search timed out")
    if tool_name == "data.run_sql" and r < float(fi.get("data_run_sql_timeout_rate", 0.0)):
        time.sleep(0.12)
        raise ToolError("UPSTREAM_TIMEOUT", "db query timed out")

    time.sleep(0.02)
    if tool_name == "itsm.get_incident":
        resp = {"incident_id": payload["incident_id"], "severity": "P2", "status": "NEW", "summary": "Payments latency reported (untriaged)", "details": "Auto-ingested alert. Need impact quantification."}
    elif tool_name == "data.run_sql":
        resp = {"rows": [{"region": "us-east", "p95_ms": 1800, "baseline_p95_ms": 420, "error_rate": 0.021}], "row_count": 1, "execution_ms": 35, "result_fingerprint": hash_obj(payload), "evidence_ref": {"evidence_id": payload["evidence_id"], "fingerprint": hash_obj(payload), "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}
    elif tool_name == "logs.search":
        resp = {"hits": [{"ts": "2026-02-17T14:02:01Z", "level": "ERROR", "message": "upstream timeout processor=bankA trace=abc123"}, {"ts": "2026-02-17T14:02:02Z", "level": "WARN", "message": "retrying request id=tx_7781"}], "hit_count": 2, "search_ms": 42, "evidence_ref": {"evidence_id": payload["evidence_id"], "fingerprint": hash_obj(payload), "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}
    elif tool_name == "grc.classify_and_redact":
        redacted = payload["text"]
        tags: List[str] = []
        for patt, tag, repl in [
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "EMAIL", "[REDACTED_EMAIL]"),
            (r"\b(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b", "PHONE", "[REDACTED_PHONE]"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "SSN", "[REDACTED_SSN]"),
            (r"\b(?:\d[ -]*?){13,19}\b", "CARD", "[REDACTED_CARD]"),
        ]:
            if re.search(patt, redacted):
                tags.append(tag)
                redacted = re.sub(patt, repl, redacted)
        resp = {"redacted_text": redacted, "pii_found": bool(tags), "tags": tags, "confidence": 0.90 if tags else 0.10}
    elif tool_name == "comms.send_update":
        resp = {"message_id": "msg_" + hash_obj(payload), "sent_ms": 18}
    else:
        raise ValueError(tool_name)

    return resp, (time.time() - start) * 1000.0


def simulate_workflow(s: Dict[str, Any], cfg: Dict[str, Any]) -> RunResult:
    t0 = time.time()
    scenario_id = s["scenario_id"]
    constraints = s["constraints"]
    controls = cfg.get("controls", {})
    fi = cfg.get("failure_injection", {})
    policy = s.get("policy_profile", "FINTECH_DEFAULT")
    critical_logs = bool(s.get("expected_outputs", {}).get("logs_required", False))
    deadline_budget_ratio = float(constraints.get("deadline_budget_ratio", 0.8))

    deadline_ms = int((time.time() + (float(constraints["latency_p95_slo_s"]) * deadline_budget_ratio)) * 1000)
    breaker_state: Dict[str, Dict[str, Any]] = {}
    tool_total = 0
    tool_valid = 0
    notes = [f"policy={policy}"]

    try:
        inc_payload = {"incident_id": s["initial_state_ref"]["incident_id"], "_fi": fi}
        incident = call_with_controls("itsm.get_incident", inc_payload, deadline_ms, controls, breaker_state, mock_tool_call)
        tool_total += 1; tool_valid += 1 if validate_call("itsm.get_incident", inc_payload, incident) else 0

        sql_payload = {"query": "SELECT region, p95_ms FROM metrics LIMIT 50", "purpose": "triage", "evidence_id": f"{scenario_id}-sql-1", "_fi": fi}
        sql_out = call_with_controls("data.run_sql", sql_payload, deadline_ms, controls, breaker_state, mock_tool_call)
        tool_total += 1; tool_valid += 1 if validate_call("data.run_sql", sql_payload, sql_out) else 0

        logs_evidence, logs_errors = [], []
        logs_queries = s.get("runtime", {}).get("logs_queries", ["timeout OR 5xx", "processor=bankA OR retrying request"])
        for idx, query in enumerate(logs_queries, start=1):
            lp = {"query": query, "time_range": {"start": "2026-02-17T13:50:00Z", "end": "2026-02-17T14:10:00Z"}, "evidence_id": f"{scenario_id}-logs-{idx}", "_fi": fi}
            try:
                out = call_with_controls("logs.search", lp, deadline_ms, controls, breaker_state, mock_tool_call)
                logs_evidence.append(out["evidence_ref"])
                tool_total += 1; tool_valid += 1 if validate_call("logs.search", lp, out) else 0
            except ToolError as e:
                logs_errors.append(e.code)

        if logs_errors:
            notes.append(f"degraded_logs={','.join(logs_errors)}")
        if critical_logs and not logs_evidence:
            raise ToolError("DEGRADED_MODE_BLOCKED", "scenario requires logs evidence")

        evidence_refs = [sql_out["evidence_ref"], *logs_evidence]
        evidence_line = "upstream timeouts observed" if logs_evidence else f"logs unavailable ({logs_errors[-1]})"
        msg = f"[{scenario_id}] Incident {incident['incident_id']} triage update\n- Current: severity={incident['severity']} status={incident['status']}\n- Evidence: p95 latency elevated in us-east; {evidence_line}\n- Proposed next: assign to Payments-OnCall; consider processor failover\n- EvidenceRefs: {evidence_refs}"

        red = call_with_controls("grc.classify_and_redact", {"text": msg, "policy": policy, "_fi": fi}, deadline_ms, controls, breaker_state, mock_tool_call)
        tool_total += 1; tool_valid += 1 if validate_call("grc.classify_and_redact", {"text": msg, "policy": policy}, red) else 0
        comms = call_with_controls("comms.send_update", {"channel": "#inc-payments", "message": red["redacted_text"], "idempotency_key": f"{scenario_id}-comms-1", "_fi": fi}, deadline_ms, controls, breaker_state, mock_tool_call)
        tool_total += 1; tool_valid += 1 if validate_call("comms.send_update", {"channel": "#inc-payments", "message": red["redacted_text"], "idempotency_key": f"{scenario_id}-comms-1"}, comms) else 0

        latency_s = time.time() - t0
        est_cost_usd = (max(200, len(msg) // 4) / 1000.0) * 0.02
        avr = (tool_valid / tool_total) if tool_total else 0.0
        pcr = 1.0
        success = latency_s <= float(constraints["latency_p95_slo_s"]) and est_cost_usd <= float(constraints["cost_slo_usd"]) and pcr == 1.0
        return RunResult(scenario_id, success, latency_s, est_cost_usd, avr, compute_ecr(msg), pcr, " ".join(notes))
    except ToolError as e:
        return RunResult(scenario_id, False, time.time() - t0, 0.0, (tool_valid / tool_total) if tool_total else 0.0, 0.0, 0.0, " ".join(notes + [f"fatal={e.code}"]))
