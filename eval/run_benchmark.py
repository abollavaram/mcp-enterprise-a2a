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
