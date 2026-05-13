# AGENTS.md — Engineering Operating Rules for `mcp-enterprise-a2a`

These rules apply to the full repository unless a deeper-scoped `AGENTS.md` overrides them.

## 1) Mission and quality bar
- Keep this project **reliability/evaluation-first** for MCP-style enterprise workflows.
- Prefer measurable reliability improvements over cosmetic refactors.
- Every claim in docs must be supportable by code and/or generated artifacts.

## 2) Architecture expectations
- Keep benchmark orchestration modular (loader, controls, workflow engine, scoring/reporting).
- Avoid re-concentrating logic into one large script.
- New modules should have clear single responsibilities and low coupling.

## 3) Reliability control standards
- Retries, circuit breaker, and deadline propagation must remain independently ablatable.
- Changes to controls should preserve deterministic, seeded evaluation runs.
- If control behavior changes, update ablation scripts and report interpretation.

## 4) Scenario and benchmark rules
- Prefer adding realistic scenario knobs (critical evidence requirements, deadline budgets, degraded-mode policy) over hardcoded behavior.
- Keep scenarios explicit and documented in README.
- Avoid “fake enterprise complexity” not represented in code paths.

## 5) Validation and contracts
- Strengthen contracts incrementally (invariants first, schema checks next).
- Never silently ignore contract failures; surface them in run notes/metrics.
- Preserve action validity (AVR) semantics when extending validators.

## 6) Output artifacts
- Keep machine-readable outputs in `eval/out/` (JSON/JSONL) and human-readable report output (`.md`).
- Ensure these scripts remain runnable:
  - `python eval/run_benchmark.py`
  - `python eval/run_ablations.py`
  - `python eval/parse_ablations.py`

## 7) Documentation discipline
- README should always include:
  - problem statement
  - architecture/execution flow
  - metrics
  - current results with date
  - mocked vs real boundary
  - limitations and roadmap
- If metrics change, regenerate artifacts first, then update README numbers.

## 8) Developer workflow
- Prefer small, logical commits.
- Run relevant commands before commit and report outcomes clearly.
- Treat no-tests-found (`pytest` exit code 5) as a repo gap to document, not a silent success.

## 9) Non-goals
- Do not turn this into a generic chatbot demo.
- Do not add frontend/UI work unless it materially improves evaluation interpretation.
- Do not claim production readiness where components are mocked.

## 10) When uncertain
- Choose the option that improves reproducibility, observability, and defensibility of reliability findings.
