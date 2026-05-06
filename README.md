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
