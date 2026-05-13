# MCP Agent-to-Agent Enterprise Workflow Automation (FINTECH)

Reliability-first benchmark harness for **MCP-style enterprise workflow orchestration** in simulated fintech incident response.

## Why this project exists
Most agent demos optimize for successful tool calls in happy paths. This repo focuses on **failure-mode reliability**: do retries, circuit breakers, deadline propagation, policy gates, and evidence requirements materially improve workflow outcomes?

## What is implemented
- Scenario-driven workflow benchmark (`eval/run_benchmark.py`)
- Reliability controls (retries, circuit breaker, deadline propagation) (`eval/controls.py`)
- Mock enterprise tools with failure injection (`eval/workflow_engine.py`)
- Contract checks + light invariants (`eval/contracts.py`)
- Ablation runs for control sensitivity (`eval/run_ablations.py` / `eval/ablation.py`)
- Ablation markdown report rendering (`eval/parse_ablations.py`)

## Architecture
1. Load scenario + config
2. Execute incident triage flow:
   - `itsm.get_incident`
   - `data.run_sql`
   - repeated `logs.search`
   - `grc.classify_and_redact`
   - `comms.send_update`
3. Apply controls around each tool call
4. Score WSR/AVR/ECR/PCR + latency/cost
5. Persist artifacts in `eval/out/`

## Metrics
- **WSR**: Workflow Success Rate
- **AVR**: Action Validity Rate
- **ECR**: Evidence Coverage Rate
- **PCR**: Policy Compliance Rate
- Latency and cost SLO pass/fail per scenario

## Scenarios
- `A01`: baseline incident enrichment, degraded mode allowed for logs
- `A02`: strict reliability scenario with tighter deadline budget and `logs_required=true`

The strict scenario is what makes circuit-breaker/deadline ablations meaningfully visible.

## Runbook
```bash
python eval/run_benchmark.py
python eval/run_ablations.py
python eval/parse_ablations.py
```

Artifacts:
- `eval/out/run_results.jsonl`
- `eval/out/ablation_results.json`
- `eval/out/ablation_report.md`

## Latest results (generated 2026-05-13)
| Variant | WSR | Avg Latency (s) | p95 Latency (s) | ΔWSR vs all_controls | Δp95 vs all_controls (s) |
|---|---:|---:|---:|---:|---:|
| all_controls | 0.4313 | 0.4388 | 0.5623 | 0.0000 | 0.0000 |
| no_circuit_breaker | 0.2250 | 0.4848 | 0.5626 | -0.2063 | 0.0003 |
| no_deadline_propagation | 0.3937 | 0.6012 | 0.9036 | -0.0375 | 0.3413 |
| no_retries | 0.5375 | 0.2455 | 0.4021 | 0.1062 | -0.1602 |

## What is mocked vs real
Mocked:
- tool backends and payload semantics
- cost model
- failure injection model

Real:
- control logic (retries/breaker/deadline)
- scenario-driven orchestration + scoring
- artifact generation for reproducible ablation comparisons

## Limitations
- synthetic workload and small scenario corpus
- contract validation is still lightweight (key/invariant checks, not full JSON Schema)
- no real production telemetry ingestion

## Near-term roadmap
- Expand scenario pack with multi-incident and policy-violation cases
- Upgrade contract validation to JSON Schema + cross-tool invariants
- Split workflow policies by domain-criticality profile
- Add CI assertions on minimum expected ablation deltas
