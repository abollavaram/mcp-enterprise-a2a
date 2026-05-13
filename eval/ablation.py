from __future__ import annotations

import copy
import json
import os
import random
import statistics
from typing import Any, Dict, List

from run_benchmark import _ensure_out_dir, _load_config, _load_scenarios, _simulate_workflow

OUT_PATH = os.path.join("eval", "out", "ablation_results.json")


def _run_many(cfg: Dict[str, Any], scenarios: List[Dict[str, Any]], runs: int, seed: int) -> Dict[str, float]:
    rows = []
    for i in range(runs):
        random.seed(seed + i)
        for s in scenarios:
            rows.append(_simulate_workflow(s, cfg))

    total = len(rows)
    successes = sum(1 for r in rows if r.success)
    latencies = [r.latency_s for r in rows]
    return {
        "runs": total,
        "wsr": (successes / total) if total else 0.0,
        "avg_latency_s": statistics.fmean(latencies) if latencies else 0.0,
        "p95_latency_s": sorted(latencies)[max(0, int(0.95 * len(latencies)) - 1)] if latencies else 0.0,
    }


def main() -> None:
    _ensure_out_dir()
    base_cfg = _load_config()
    scenarios = _load_scenarios(limit=None)

    # Tighten latency budget and increase transient failure rates to make control ablations measurable.
    for scenario in scenarios:
        scenario["constraints"]["latency_p95_slo_s"] = 0.6

    base_cfg["failure_injection"] = {
        "logs_search_timeout_rate": 0.55,
        "logs_search_down_rate": 0.25,
        "data_run_sql_timeout_rate": 0.20,
    }

    stress_runs = 80
    seed = 20260513

    variants = {
        "all_controls": {
            "retries_enabled": True,
            "circuit_breaker_enabled": True,
            "deadline_propagation_enabled": True,
        },
        "no_circuit_breaker": {
            "retries_enabled": True,
            "circuit_breaker_enabled": False,
            "deadline_propagation_enabled": True,
        },
        "no_deadline_propagation": {
            "retries_enabled": True,
            "circuit_breaker_enabled": True,
            "deadline_propagation_enabled": False,
        },
        "no_retries": {
            "retries_enabled": False,
            "circuit_breaker_enabled": True,
            "deadline_propagation_enabled": True,
        },
    }

    results: Dict[str, Any] = {
        "runs_per_variant": stress_runs,
        "seed": seed,
        "variants": {},
    }

    for name, controls in variants.items():
        cfg = copy.deepcopy(base_cfg)
        cfg["controls"] = controls
        results["variants"][name] = _run_many(cfg, scenarios, runs=stress_runs, seed=seed)

    baseline = results["variants"]["all_controls"]
    sensitivity = {}
    for name, vals in results["variants"].items():
        if name == "all_controls":
            continue
        sensitivity[name] = {
            "delta_wsr_vs_all_controls": vals["wsr"] - baseline["wsr"],
            "delta_p95_latency_s_vs_all_controls": vals["p95_latency_s"] - baseline["p95_latency_s"],
        }
    results["ablation_sensitivity"] = sensitivity

    with open(OUT_PATH, "w", encoding="utf-8") as fp:
        json.dump(results, fp, indent=2)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
