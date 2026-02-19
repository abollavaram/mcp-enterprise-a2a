# Architecture

## SLOs
- Latency SLO: p95 <= 12s per workflow
- Cost SLO: <= $0.08 per successful workflow
- Policy profile: FINTECH_DEFAULT (PII detection + redaction enforced)

## High-level diagram
[User/Trigger]
|
v
[Workflow API]
|
v
[Orchestrator Agent] <-- budgets, deadlines, retries, circuit breakers
|
+--> [Planner Agent] ---> [Task DAG]
|
+--> [Evidence Agent] ---> MCP Tools (READ)
|
+--> [Evaluator Agent] ---> Quality & policy gates
|
v
[WRITE ops if allowed] ---> MCP Tools (WRITE, idempotent)
|
v
[Outcome + Evidence Pack + TraceID + Cost]



## Design principles
- Contract-first tool interfaces (schema + invariants + error taxonomy)
- Evidence-linked outputs (no claims without evidence_refs)
- Strict policy gating (PII must be redacted before comms/write)
- Deterministic evaluation harness with repeatable scenarios
