from __future__ import annotations

import json
import os
import time
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from rich import print


SCENARIO_DIR = os.path.join("eval", "scenarios")
OUT_DIR = os.path.join("eval", "out")


@dataclass
class RunResult:
    scenario_id: str
    success: bool
    latency_s: float
    est_cost_usd: float
    avr: float
    ecr: float
    pcr: float
    notes: str

def _has_keys(obj: Dict[str, Any], keys: List[str]) -> bool:
    return all(k in obj for k in keys)


def _validate_call(tool_name: str, payload: Dict[str, Any], response: Dict[str, Any]) -> bool:
    """
    Minimal contract validation (phase-1).
    Later replaced by JSON Schema validation + invariants.
    """
    if tool_name == "itsm.get_incident":
        return _has_keys(payload, ["incident_id"]) and _has_keys(response, ["incident_id", "severity", "status", "summary", "details"])

    if tool_name == "data.run_sql":
        return _has_keys(payload, ["query", "purpose", "evidence_id"]) and _has_keys(
            response, ["rows", "row_count", "execution_ms", "result_fingerprint", "evidence_ref"]
        )

    if tool_name == "logs.search":
        return _has_keys(payload, ["query", "time_range", "evidence_id"]) and _has_keys(
            response, ["hits", "hit_count", "search_ms", "evidence_ref"]
        )

    if tool_name == "grc.classify_and_redact":
        return _has_keys(payload, ["text", "policy"]) and _has_keys(response, ["redacted_text", "pii_found", "tags", "confidence"])

    if tool_name == "comms.send_update":
        return _has_keys(payload, ["channel", "message", "idempotency_key"]) and _has_keys(response, ["message_id", "sent_ms"])

    return False


def _compute_ecr(message: str) -> float:
    """
    Phase-1 ECR: claim lines are '- ...' lines.
    Evidence-linked if EvidenceRefs present and non-empty.
    """
    claim_lines = [ln for ln in message.splitlines() if ln.strip().startswith("- ")]
    if not claim_lines:
        return 0.0

    has_evidence = "EvidenceRefs:" in message and "[" in message and "]" in message
    linked = len(claim_lines) if has_evidence else 0
    return linked / len(claim_lines)



def _load_scenarios(limit: int | None = None) -> List[Dict[str, Any]]:
    files = sorted([f for f in os.listdir(SCENARIO_DIR) if f.endswith(".json")])
    if limit is not None:
        files = files[:limit]
    scenarios: List[Dict[str, Any]] = []
    for f in files:
        path = os.path.join(SCENARIO_DIR, f)
        with open(path, "r", encoding="utf-8") as fp:
            scenarios.append(json.load(fp))
    return scenarios


def _ensure_out_dir() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)


def _hash_obj(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _mock_tool_call(tool_name: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], float]:
    """
    MOCK ONLY.
    Returns (response, tool_latency_ms).
    """
    start = time.time()

    # Simulate tool latency
    time.sleep(0.02)

    if tool_name == "itsm.get_incident":
        resp = {
            "incident_id": payload["incident_id"],
            "severity": "P2",
            "status": "NEW",
            "summary": "Payments latency reported (untriaged)",
            "details": "Auto-ingested alert. Need impact quantification.",
        }
    elif tool_name == "data.run_sql":
        # Return synthetic rows; real DB later
        resp = {
            "rows": [{"region": "us-east", "p95_ms": 1800, "baseline_p95_ms": 420, "error_rate": 0.021}],
            "row_count": 1,
            "execution_ms": 35,
            "result_fingerprint": _hash_obj(payload),
            "evidence_ref": {"evidence_id": payload["evidence_id"], "fingerprint": _hash_obj(payload), "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        }
    elif tool_name == "logs.search":
        resp = {
            "hits": [
                {"ts": "2026-02-17T14:02:01Z", "level": "ERROR", "message": "upstream timeout processor=bankA trace=abc123"},
                {"ts": "2026-02-17T14:02:02Z", "level": "WARN", "message": "retrying request id=tx_7781"},
            ],
            "hit_count": 2,
            "search_ms": 42,
            "evidence_ref": {"evidence_id": payload["evidence_id"], "fingerprint": _hash_obj(payload), "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        }
    elif tool_name == "grc.classify_and_redact":
        import re

        text = payload["text"]
        policy = payload.get("policy", "FINTECH_DEFAULT")

        tags = []
        redacted = text

    # EMAIL
        email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        if email_re.search(redacted):
            tags.append("EMAIL")
            redacted = email_re.sub("[REDACTED_EMAIL]", redacted)

    # PHONE (simple US/IN-ish patterns; good enough for deterministic gating)
        phone_re = re.compile(r"\b(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
        if phone_re.search(redacted):
            tags.append("PHONE")
            redacted = phone_re.sub("[REDACTED_PHONE]", redacted)

    # SSN (US)
        ssn_re = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
        if ssn_re.search(redacted):
            tags.append("SSN")
            redacted = ssn_re.sub("[REDACTED_SSN]", redacted)

    # CARD-like (13-19 digits, allowing spaces/dashes)
        card_re = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
        if card_re.search(redacted):
            tags.append("CARD")
            redacted = card_re.sub("[REDACTED_CARD]", redacted)

        pii_found = len(tags) > 0

    # Confidence heuristic (deterministic)
        confidence = 0.90 if pii_found else 0.10

        resp = {
            "redacted_text": redacted,
            "pii_found": pii_found,
            "tags": tags,
            "confidence": confidence,
        }
    elif tool_name == "comms.send_update":
        resp = {"message_id": "msg_" + _hash_obj(payload), "sent_ms": 18}
    else:
        raise ValueError(f"Unknown tool: {tool_name}")

    end = time.time()
    return resp, (end - start) * 1000.0


def _simulate_workflow(s: Dict[str, Any]) -> RunResult:
    """
    Baseline: collect evidence -> redaction -> stakeholder update (mock).
    Later: enforce contracts, retries, breakers, budgets, and real scoring.
    """
    t0 = time.time()
    tool_total = 0
    tool_valid = 0


    scenario_id = s["scenario_id"]
    slo_latency = float(s["constraints"]["latency_p95_slo_s"])
    slo_cost = float(s["constraints"]["cost_slo_usd"])
    policy = s.get("policy_profile", "FINTECH_DEFAULT")

    # Tool calls (mock)
    payload_inc = {"incident_id": s["initial_state_ref"]["incident_id"]}
    incident, _ = _mock_tool_call("itsm.get_incident", payload_inc)
    tool_total += 1
    tool_valid += 1 if _validate_call("itsm.get_incident", payload_inc, incident) else 0

    payload_sql = {"query": "SELECT region, p95_ms FROM metrics LIMIT 50", "purpose": "triage", "evidence_id": f"{scenario_id}-sql-1"}
    sql_out, _ = _mock_tool_call("data.run_sql", payload_sql)
    tool_total += 1
    tool_valid += 1 if _validate_call("data.run_sql", payload_sql, sql_out) else 0


    payload_logs = {"query": "timeout OR 5xx", "time_range": {"start": "2026-02-17T13:50:00Z", "end": "2026-02-17T14:10:00Z"}, "evidence_id": f"{scenario_id}-logs-1"}
    logs_out, _ = _mock_tool_call("logs.search", payload_logs)
    tool_total += 1
    tool_valid += 1 if _validate_call("logs.search", payload_logs, logs_out) else 0


    # Draft update with evidence refs (simple)
    evidence_refs = [sql_out["evidence_ref"], logs_out["evidence_ref"]]
    msg = (
        f"[{scenario_id}] Incident {incident['incident_id']} triage update\n"
        f"- Current: severity={incident['severity']} status={incident['status']}\n"
        f"- Evidence: p95 latency elevated in us-east; upstream timeouts observed\n"
        f"- Proposed next: assign to Payments-OnCall; consider processor failover\n"
        f"- EvidenceRefs: {evidence_refs}"
    )

    payload_redact = {"text": msg, "policy": policy, "return_tags": True}
    redacted, _ = _mock_tool_call("grc.classify_and_redact", payload_redact)
    tool_total += 1
    tool_valid += 1 if _validate_call("grc.classify_and_redact", payload_redact, redacted) else 0

    # Send comms (idempotent)
    payload_comms = {"channel": "#inc-payments", "message": redacted["redacted_text"], "idempotency_key": f"{scenario_id}-comms-1"}
    comms_out, _ = _mock_tool_call("comms.send_update", payload_comms)
    tool_total += 1
    tool_valid += 1 if _validate_call("comms.send_update", payload_comms, comms_out) else 0



    latency_s = time.time() - t0

    # EST cost model (placeholder): tokens ~ proportional to message length
    est_tokens = max(200, len(msg) // 4)
    est_cost_usd = (est_tokens / 1000.0) * 0.02  # pretend $0.02 per 1K tokens

    # Placeholder scoring (we’ll replace with real scorers)
    avr = (tool_valid / tool_total) if tool_total else 0.0
    ecr = _compute_ecr(msg)

    # Policy compliance:
# - If PII not found => compliant
# - If PII found => compliant only if redaction placeholders are present
    placeholders = ["[REDACTED_EMAIL]", "[REDACTED_PHONE]", "[REDACTED_SSN]", "[REDACTED_CARD]"]
    pcr = 1.0 if (not redacted["pii_found"]) else (1.0 if any(p in redacted["redacted_text"] for p in placeholders) else 0.0)



    success = (latency_s <= slo_latency) and (est_cost_usd <= slo_cost) and (pcr == 1.0)

    notes = f"latency_slo={slo_latency}s cost_slo=${slo_cost} policy={policy}"
    return RunResult(scenario_id, success, latency_s, est_cost_usd, avr, ecr, pcr, notes)


def main() -> None:
    _ensure_out_dir()
    scenarios = _load_scenarios(limit=None)

    results: List[RunResult] = []
    for s in scenarios:
        r = _simulate_workflow(s)
        results.append(r)

    # Print summary
    total = len(results)
    passed = sum(1 for r in results if r.success)
    print(f"\n[bold]Runs:[/bold] {total}  [bold]Passed:[/bold] {passed}  [bold]WSR:[/bold] {passed/total if total else 0:.3f}")

    # Save JSONL
    out_path = os.path.join(OUT_DIR, "run_results.jsonl")
    with open(out_path, "w", encoding="utf-8") as fp:
        for r in results:
            fp.write(json.dumps(r.__dict__) + "\n")

    # Basic report
    for r in results:
        print(f"- {r.scenario_id}: success={r.success} latency={r.latency_s:.2f}s cost=${r.est_cost_usd:.4f} AVR={r.avr:.2f} ECR={r.ecr:.2f} PCR={r.pcr:.2f}")


if __name__ == "__main__":
    main()
