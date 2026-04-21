from __future__ import annotations

import copy
import json
import os
import subprocess
from typing import Any, Dict, List

CONFIG_PATH = os.path.join("eval", "config.json")
OUT_PATH = os.path.join("eval", "out", "ablation_summary.json")

ABLATIONS = {
    "A0_all_on": {
        "controls": {"retries_enabled": True, "circuit_breaker_enabled": True, "deadline_propagation_enabled": True}
    },
    "A1_no_retries": {
        "controls": {"retries_enabled": False, "circuit_breaker_enabled": True, "deadline_propagation_enabled": True}
    },
    "A2_no_breaker": {
        "controls": {"retries_enabled": True, "circuit_breaker_enabled": False, "deadline_propagation_enabled": True}
    },
    "A3_no_deadline": {
        "controls": {"retries_enabled": True, "circuit_breaker_enabled": True, "deadline_propagation_enabled": False}
    }
}

def _load_cfg() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fp:
        return json.load(fp)

def _save_cfg(cfg: Dict[str, Any]) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as fp:
        json.dump(cfg, fp, indent=2)

def _run_once() -> Dict[str, Any]:
    p = subprocess.run(["python", "eval/run_benchmark.py"], capture_output=True, text=True)
    return {"returncode": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}

def main() -> None:
    base = _load_cfg()
    results: List[Dict[str, Any]] = []

    for name, patch in ABLATIONS.items():
        cfg = copy.deepcopy(base)
        cfg["controls"].update(patch["controls"])
        _save_cfg(cfg)

        run = _run_once()
        results.append({"ablation": name, "controls": cfg["controls"], "run": run})

    _save_cfg(base)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as fp:
        json.dump(results, fp, indent=2)

    print(f"Wrote {OUT_PATH}")

if __name__ == "__main__":
    main()