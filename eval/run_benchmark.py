from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from rich import print

from models import RunResult
from workflow_engine import simulate_workflow

SCENARIO_DIR = os.path.join("eval", "scenarios")
OUT_DIR = os.path.join("eval", "out")
CONFIG_PATH = os.path.join("eval", "config.json")


def _ensure_out_dir() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)


def _load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fp:
        return json.load(fp)


def _load_scenarios(limit: int | None = None) -> List[Dict[str, Any]]:
    files = sorted([f for f in os.listdir(SCENARIO_DIR) if f.endswith(".json")])
    if limit is not None:
        files = files[:limit]
    return [json.load(open(os.path.join(SCENARIO_DIR, f), "r", encoding="utf-8")) for f in files]



=======


=======
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

        # logs.search x2 (may fail; we degrade gracefully)
        logs_evidence = []
        logs_errors = []
        for idx, query in enumerate(["timeout OR 5xx", "processor=bankA OR retrying request"], start=1):
            payload_logs = {
                "query": query,
                "time_range": {"start": "2026-02-17T13:50:00Z", "end": "2026-02-17T14:10:00Z"},
                "evidence_id": f"{scenario_id}-logs-{idx}",
                "_fi": fi,
            }
            try:
                logs_out = _call_with_controls("logs.search", payload_logs, deadline_ms, controls, breaker_state)
                logs_evidence.append(logs_out["evidence_ref"])
                tool_total += 1
                tool_valid += 1 if _validate_call("logs.search", payload_logs, logs_out) else 0
            except ToolError as e:
                logs_errors.append(e.code)

        if logs_errors:
            notes_parts.append(f"degraded_logs={','.join(logs_errors)}")

        # Evidence refs
        evidence_refs = [sql_out["evidence_ref"], *logs_evidence]

        # Draft update
        evidence_line = "upstream timeouts observed" if logs_evidence else f"logs unavailable ({logs_errors[-1]})"
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
main
 main
def main() -> None:
    _ensure_out_dir()
    cfg = _load_config()
    scenarios = _load_scenarios(limit=None)

    results: List[RunResult] = [simulate_workflow(s, cfg) for s in scenarios]
    total = len(results)
    passed = sum(1 for r in results if r.success)
    wsr = (passed / total) if total else 0.0
    print(f"\n[bold]Runs:[/bold] {total}  [bold]Passed:[/bold] {passed}  [bold]WSR:[/bold] {wsr:.3f}")

    with open(os.path.join(OUT_DIR, "run_results.jsonl"), "w", encoding="utf-8") as fp:
        for r in results:
            fp.write(json.dumps(r.__dict__) + "\n")

    for r in results:
        print(f"- {r.scenario_id}: success={r.success} latency={r.latency_s:.2f}s cost=${r.est_cost_usd:.4f} AVR={r.avr:.2f} ECR={r.ecr:.2f} PCR={r.pcr:.2f} notes={r.notes}")


if __name__ == "__main__":
    main()
