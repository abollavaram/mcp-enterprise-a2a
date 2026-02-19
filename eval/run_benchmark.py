from __future__ import annotations

import json
import os
import time
import hashlib
import random
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from rich import print

SCENARIO_DIR = os.path.join("eval", "scenarios")
OUT_DIR = os.path.join("eval", "out")
CONFIG_PATH = os.path.join("eval", "config.json")


# -------------------------
# Data structures
# -------------------------
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


class ToolError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# -------------------------
# Utilities
# -------------------------
def _ensure_out_dir() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)


def _load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fp:
        return json.load(fp)


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


def _hash_obj(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _has_keys(obj: Dict[str, Any], keys: List[str]) -> bool:
    return all(k in obj for k in keys)


def _validate_call(tool_name: str, payload: Dict[str, Any], response: Dict[str, Any]) -> bool:
    """
    Minimal contract validation (phase-1).
    Replaced later by JSON Schema validation + invariants.
    """
    if tool_name == "itsm.get_incident":
        return _has_keys(payload, ["incident_id"]) and _has_keys(
            response, ["incident_id", "severity", "status", "summary", "details"]
        )

    if tool_name == "data.run_sql":
        return _has_keys(payload, ["query", "purpose", "evidence_id"]) and _has_keys(
            response, ["rows", "row_count", "execution_ms", "result_fingerprint", "evidence_ref"]
        )

    if tool_name == "logs.search":
        return _has_keys(payload, ["query", "time_range", "evidence_id"]) and _has_keys(
            response, ["hits", "hit_count", "search_ms", "evidence_ref"]
        )

    if tool_name == "grc.classify_and_redact":
        return _has_keys(payload, ["text", "policy"]) and _has_keys(
            response, ["redacted_text", "pii_found", "tags", "confidence"]
        )

    if tool_name == "comms.send_update":
        return _has_keys(payload, ["channel", "message", "idempotency_key"]) and _has_keys(
            response, ["message_id", "sent_ms"]
        )

    return False


def _compute_ecr(message: str) -> float:
    """
    Phase-1 ECR:
    - claim lines are '- ...' lines
    - evidence-linked if message contains 'EvidenceRefs:' and a non-empty list representation
    """
    claim_lines = [ln for ln in message.splitlines() if ln.strip().startswith("- ")]
    if not claim_lines:
        return 0.0

    has_evidence = ("EvidenceRefs:" in message) and ("[" in message) and ("]" in message)
    linked = len(claim_lines) if has_evidence else 0
    return linked / len(claim_lines)


def _now_ms() -> int:
    return int(time.time() * 1000)


# -------------------------
# Mock tools with failure injection
# -------------------------
def _mock_tool_call(tool_name: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], float]:
    """
    MOCK ONLY.
    Returns (response, tool_latency_ms).

    Supports failure injection via payload["_fi"].
    """
    start = time.time()

    # failure injection (probabilistic)
    fi = payload.get("_fi", {})
    r = random.random()

    if tool_name == "logs.search":
        if r < float(fi.get("logs_search_down_rate", 0.0)):
            raise ToolError("UPSTREAM_DOWN", "logs backend unavailable")
        if r < float(fi.get("logs_search_down_rate", 0.0)) + float(fi.get("logs_search_timeout_rate", 0.0)):
            time.sleep(0.15)
            raise ToolError("UPSTREAM_TIMEOUT", "logs search timed out")

    if tool_name == "data.run_sql":
        if r < float(fi.get("data_run_sql_timeout_rate", 0.0)):
            time.sleep(0.12)
            raise ToolError("UPSTREAM_TIMEOUT", "db query timed out")

    # Simulate base tool latency
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
        resp = {
            "rows": [{"region": "us-east", "p95_ms": 1800, "baseline_p95_ms": 420, "error_rate": 0.021}],
            "row_count": 1,
            "execution_ms": 35,
            "result_fingerprint": _hash_obj(payload),
            "evidence_ref": {
                "evidence_id": payload["evidence_id"],
                "fingerprint": _hash_obj(payload),
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        }

    elif tool_name == "logs.search":
        resp = {
            "hits": [
                {"ts": "2026-02-17T14:02:01Z", "level": "ERROR", "message": "upstream timeout processor=bankA trace=abc123"},
                {"ts": "2026-02-17T14:02:02Z", "level": "WARN", "message": "retrying request id=tx_7781"},
            ],
            "hit_count": 2,
            "search_ms": 42,
            "evidence_ref": {
                "evidence_id": payload["evidence_id"],
                "fingerprint": _hash_obj(payload),
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        }

    elif tool_name == "grc.classify_and_redact":
        text = payload["text"]
        policy = payload.get("policy", "FINTECH_DEFAULT")
        _ = policy  # policy hook; later: policy-specific rules

        tags: List[str] = []
        redacted = text

        # EMAIL
        email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        if email_re.search(redacted):
            tags.append("EMAIL")
            redacted = email_re.sub("[REDACTED_EMAIL]", redacted)

        # PHONE (simple)
        phone_re = re.compile(r"\b(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
        if phone_re.search(redacted):
            tags.append("PHONE")
            redacted = phone_re.sub("[REDACTED_PHONE]", redacted)

        # SSN
        ssn_re = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
        if ssn_re.search(redacted):
            tags.append("SSN")
            redacted = ssn_re.sub("[REDACTED_SSN]", redacted)

        # CARD-like (13-19 digits with spaces/dashes)
        card_re = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
        if card_re.search(redacted):
            tags.append("CARD")
            redacted = card_re.sub("[REDACTED_CARD]", redacted)

        pii_found = len(tags) > 0
        confidence = 0.90 if pii_found else 0.10

        resp = {"redacted_text": redacted, "pii_found": pii_found, "tags": tags, "confidence": confidence}

    elif tool_name == "comms.send_update":
        resp = {"message_id": "msg_" + _hash_obj(payload), "sent_ms": 18}

    else:
        raise ValueError(f"Unknown tool: {tool_name}")

    end = time.time()
    return resp, (end - start) * 1000.0


# -------------------------
# Controls: retries, breaker, deadline
# -------------------------
def _call_with_controls(
    tool_name: str,
    payload: Dict[str, Any],
    deadline_ms: int,
    controls: Dict[str, Any],
    breaker_state: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    retries_enabled = bool(controls.get("retries_enabled", True))
    breaker_enabled = bool(controls.get("circuit_breaker_enabled", True))
    deadline_enabled = bool(controls.get("deadline_propagation_enabled", True))

    # circuit breaker check
    if breaker_enabled:
        st = breaker_state.setdefault(tool_name, {"fails": 0, "open_until_ms": 0})
        if _now_ms() < int(st["open_until_ms"]):
            raise ToolError("UPSTREAM_DOWN", f"circuit open for {tool_name}")

    attempt = 0
    max_attempts = 3 if retries_enabled else 1
    backoff_ms = 50

    while True:
        attempt += 1

        if deadline_enabled and (_now_ms() > deadline_ms):
            raise ToolError("UPSTREAM_TIMEOUT", f"deadline exceeded before calling {tool_name}")

        try:
            resp, _ = _mock_tool_call(tool_name, payload)

            # success => reset breaker fails
            if breaker_enabled:
                breaker_state[tool_name]["fails"] = 0
            return resp

        except ToolError as e:
            # breaker update
            if breaker_enabled:
                st = breaker_state.setdefault(tool_name, {"fails": 0, "open_until_ms": 0})
                st["fails"] = int(st["fails"]) + 1
                if st["fails"] >= 2:
                    st["open_until_ms"] = _now_ms() + 500  # open for 500ms

            retryable = e.code in {"UPSTREAM_TIMEOUT", "UPSTREAM_DOWN", "RATE_LIMIT"}
            if (not retries_enabled) or (not retryable) or (attempt >= max_attempts):
                raise

            # backoff (respect deadline)
            if deadline_enabled and (_now_ms() + backoff_ms > deadline_ms):
                raise ToolError("UPSTREAM_TIMEOUT", f"deadline exceeded during backoff for {tool_name}")

            time.sleep(backoff_ms / 1000.0)
            backoff_ms *= 2


# -------------------------
# Workflow simulation
# -------------------------
def _simulate_workflow(s: Dict[str, Any], cfg: Dict[str, Any]) -> RunResult:
    t0 = time.time()

    scenario_id = s["scenario_id"]
    slo_latency = float(s["constraints"]["latency_p95_slo_s"])
    slo_cost = float(s["constraints"]["cost_slo_usd"])
    policy = s.get("policy_profile", "FINTECH_DEFAULT")

    controls = cfg.get("controls", {})
    fi = cfg.get("failure_injection", {})

    breaker_state: Dict[str, Dict[str, Any]] = {}

    # internal deadline: 80% of SLO for tool ops
    deadline_ms = int((time.time() + (slo_latency * 0.8)) * 1000)

    tool_total = 0
    tool_valid = 0

    notes_parts = [f"policy={policy}"]

    try:
        # itsm.get_incident
        payload_inc = {"incident_id": s["initial_state_ref"]["incident_id"], "_fi": fi}
        incident = _call_with_controls("itsm.get_incident", payload_inc, deadline_ms, controls, breaker_state)
        tool_total += 1
        tool_valid += 1 if _validate_call("itsm.get_incident", payload_inc, incident) else 0

        # data.run_sql
        payload_sql = {
            "query": "SELECT region, p95_ms FROM metrics LIMIT 50",
            "purpose": "triage",
            "evidence_id": f"{scenario_id}-sql-1",
            "_fi": fi,
        }
        sql_out = _call_with_controls("data.run_sql", payload_sql, deadline_ms, controls, breaker_state)
        tool_total += 1
        tool_valid += 1 if _validate_call("data.run_sql", payload_sql, sql_out) else 0

        # logs.search (may fail; we degrade gracefully)
        logs_out = None
        logs_err = None
        payload_logs = {
            "query": "timeout OR 5xx",
            "time_range": {"start": "2026-02-17T13:50:00Z", "end": "2026-02-17T14:10:00Z"},
            "evidence_id": f"{scenario_id}-logs-1",
            "_fi": fi,
        }
        try:
            logs_out = _call_with_controls("logs.search", payload_logs, deadline_ms, controls, breaker_state)
            tool_total += 1
            tool_valid += 1 if _validate_call("logs.search", payload_logs, logs_out) else 0
        except ToolError as e:
            logs_err = e
            notes_parts.append(f"degraded_logs={e.code}")

        # Evidence refs
        evidence_refs = [sql_out["evidence_ref"]]
        if logs_out is not None:
            evidence_refs.append(logs_out["evidence_ref"])

        # Draft update
        evidence_line = "upstream timeouts observed" if logs_out is not None else f"logs unavailable ({logs_err.code})"
        msg = (
            f"[{scenario_id}] Incident {incident['incident_id']} triage update\n"
            f"- Current: severity={incident['severity']} status={incident['status']}\n"
            f"- Evidence: p95 latency elevated in us-east; {evidence_line}\n"
            f"- Proposed next: assign to Payments-OnCall; consider processor failover\n"
            f"- EvidenceRefs: {evidence_refs}"
        )

        # redact
        payload_redact = {"text": msg, "policy": policy, "return_tags": True, "_fi": fi}
        redacted = _call_with_controls("grc.classify_and_redact", payload_redact, deadline_ms, controls, breaker_state)
        tool_total += 1
        tool_valid += 1 if _validate_call("grc.classify_and_redact", payload_redact, redacted) else 0

        # comms
        payload_comms = {
            "channel": "#inc-payments",
            "message": redacted["redacted_text"],
            "idempotency_key": f"{scenario_id}-comms-1",
            "_fi": fi,
        }
        comms_out = _call_with_controls("comms.send_update", payload_comms, deadline_ms, controls, breaker_state)
        tool_total += 1
        tool_valid += 1 if _validate_call("comms.send_update", payload_comms, comms_out) else 0

        # scoring
        latency_s = time.time() - t0

        est_tokens = max(200, len(msg) // 4)
        est_cost_usd = (est_tokens / 1000.0) * 0.02  # placeholder pricing model

        avr = (tool_valid / tool_total) if tool_total else 0.0
        ecr = _compute_ecr(msg)

        placeholders = ["[REDACTED_EMAIL]", "[REDACTED_PHONE]", "[REDACTED_SSN]", "[REDACTED_CARD]"]
        pcr = 1.0 if (not redacted["pii_found"]) else (1.0 if any(p in redacted["redacted_text"] for p in placeholders) else 0.0)

        success = (latency_s <= slo_latency) and (est_cost_usd <= slo_cost) and (pcr == 1.0)

        notes_parts.append(f"latency_slo={slo_latency}s")
        notes_parts.append(f"cost_slo=${slo_cost}")

        return RunResult(
            scenario_id=scenario_id,
            success=success,
            latency_s=latency_s,
            est_cost_usd=est_cost_usd,
            avr=avr,
            ecr=ecr,
            pcr=pcr,
            notes=" ".join(notes_parts),
        )

    except ToolError as e:
        # If a critical path fails (incident/sql/redact/comms), we mark run failed but DO NOT crash the whole program.
        latency_s = time.time() - t0
        return RunResult(
            scenario_id=scenario_id,
            success=False,
            latency_s=latency_s,
            est_cost_usd=0.0,
            avr=(tool_valid / tool_total) if tool_total else 0.0,
            ecr=0.0,
            pcr=0.0,
            notes=" ".join(notes_parts + [f"fatal={e.code}"]),
        )


# -------------------------
# Main
# -------------------------
def main() -> None:
    _ensure_out_dir()
    cfg = _load_config()
    scenarios = _load_scenarios(limit=None)

    results: List[RunResult] = []
    for s in scenarios:
        r = _simulate_workflow(s, cfg)
        results.append(r)

    total = len(results)
    passed = sum(1 for r in results if r.success)
    wsr = (passed / total) if total else 0.0
    print(f"\n[bold]Runs:[/bold] {total}  [bold]Passed:[/bold] {passed}  [bold]WSR:[/bold] {wsr:.3f}")

    out_path = os.path.join(OUT_DIR, "run_results.jsonl")
    with open(out_path, "w", encoding="utf-8") as fp:
        for r in results:
            fp.write(json.dumps(r.__dict__) + "\n")

    for r in results:
        print(
            f"- {r.scenario_id}: success={r.success} latency={r.latency_s:.2f}s "
            f"cost=${r.est_cost_usd:.4f} AVR={r.avr:.2f} ECR={r.ecr:.2f} PCR={r.pcr:.2f} notes={r.notes}"
        )


if __name__ == "__main__":
    main()
