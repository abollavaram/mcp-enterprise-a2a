from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

IN_PATH = os.path.join("eval", "out", "ablation_summary.json")
OUT_PATH = os.path.join("eval", "out", "ablation_metrics.json")


def _extract_metrics(stdout: str) -> Dict[str, Any]:
    """
    Extract:
    Runs: 10  Passed: 9  WSR: 0.900
    """
    m = re.search(r"Runs:\s*(\d+)\s+Passed:\s*(\d+)\s+WSR:\s*([0-9.]+)", stdout)
    if not m:
        return {
            "runs": None,
            "passed": None,
            "wsr": None
        }

    return {
        "runs": int(m.group(1)),
        "passed": int(m.group(2)),
        "wsr": float(m.group(3))
    }


def main() -> None:
    with open(IN_PATH, "r", encoding="utf-8") as fp:
        data: List[Dict[str, Any]] = json.load(fp)

    out: List[Dict[str, Any]] = []

    for item in data:
        ablation = item["ablation"]
        controls = item["controls"]
        run = item["run"]
        metrics = _extract_metrics(run.get("stdout", ""))

        out.append({
            "ablation": ablation,
            "controls": controls,
            "returncode": run.get("returncode"),
            "runs": metrics["runs"],
            "passed": metrics["passed"],
            "wsr": metrics["wsr"],
            "stderr": run.get("stderr", "")
        })

    with open(OUT_PATH, "w", encoding="utf-8") as fp:
        json.dump(out, fp, indent=2)

    print(f"Wrote {OUT_PATH}")
    print("\nAblation Summary:")
    for row in out:
        print(
            f"- {row['ablation']}: "
            f"runs={row['runs']} passed={row['passed']} wsr={row['wsr']} "
            f"controls={row['controls']}"
        )


if __name__ == "__main__":
    main()