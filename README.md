# MCP Agent-to-Agent Enterprise Workflow Automation (FINTECH)

Benchmark-driven reliability harness for **MCP-style enterprise workflow orchestration** under simulated fintech incident-response scenarios.

This project focuses on a problem most agent demos ignore: **reliability under failure**.  
Instead of only showing tool-calling behavior, it evaluates whether controls such as **retries, circuit breakers, deadline propagation, policy gating, and evidence linkage** improve workflow outcomes in enterprise-style workflows.

---

## Problem Statement

Enterprise AI workflows fail in predictable ways:

- transient tool timeouts
- backend outages
- invalid tool inputs/outputs
- missing evidence for claims
- policy/compliance violations
- wasted latency from uncontrolled retries
- cost growth without execution budgets

This project builds a **scenario-driven evaluation harness** for these failure modes and measures whether reliability controls materially improve outcomes.

---

## Current Scope

The current implementation simulates an incident-triage workflow across five enterprise domains:

- **ITSM** — incident retrieval / update
- **Data** — SQL-style evidence lookup
- **Logs** — operational signal lookup
- **GRC** — PII detection + redaction
- **Comms** — stakeholder update publishing

It currently includes:

- scenario-based benchmark execution
- mock tool orchestration
- config-driven failure injection
- retries, circuit breaker, and deadline propagation
- evidence-linked output generation
- policy-aware redaction
- evaluation metrics:
  - **WSR** — Workflow Success Rate
  - **AVR** — Action Validity Rate
  - **ECR** — Evidence Coverage Rate
  - **PCR** — Policy Compliance Rate
- ablation runner for control comparisons
- CI-backed benchmark execution

---

## SLOs

- **Latency SLO:** p95 <= 12s per workflow
- **Cost SLO:** <= $0.08 per successful workflow
- **Policy Profile:** `FINTECH_DEFAULT`

---

## Current Architecture

```text
Scenario JSON
   |
   v
Workflow Runner / Orchestrator
   |
   +--> ITSM tool
   +--> Data tool
   +--> Logs tool
   +--> GRC tool
   +--> Comms tool
   |
   v
Reliability Controls
   - retries
   - circuit breaker
   - deadline propagation
   |
   v
Evaluation Metrics
   - WSR
   - AVR
   - ECR
   - PCR
   - latency
   - cost
   |
   v
Ablation Runner


## Latest Ablation Results (2026-05-13)

Stress configuration used for sensitivity testing:
- 80 runs per variant (seed `20260513`)
- tighter workflow latency SLO set to `0.6s`
- elevated failure injection rates (`logs timeout=0.55`, `logs down=0.25`, `sql timeout=0.20`)

| Variant | WSR | Avg Latency (s) | p95 Latency (s) | ΔWSR vs all_controls | Δp95 vs all_controls (s) |
|---|---:|---:|---:|---:|---:|
| all_controls | 0.7375 | 0.4412 | 0.5821 | 0.0000 | 0.0000 |
| no_circuit_breaker | 0.3625 | 0.4859 | 0.5828 | -0.3750 | 0.0007 |
| no_deadline_propagation | 0.5625 | 0.5748 | 0.8534 | -0.1750 | 0.2713 |
| no_retries | 0.8125 | 0.2513 | 0.3822 | 0.0750 | -0.1999 |

Key takeaways:
- Circuit breaker and deadline propagation now produce measurable degradation when removed under stress.
- Retries improve resilience in milder conditions, but under tight budgets can trade latency for success depending on failure mix.

Artifacts:
- Benchmark run output: `eval/out/run_results.jsonl`
- Ablation output: `eval/out/ablation_results.json`
