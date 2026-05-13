from __future__ import annotations

import json
import os

IN_PATH = os.path.join("eval", "out", "ablation_results.json")
OUT_PATH = os.path.join("eval", "out", "ablation_report.md")


def main() -> None:
    data = json.load(open(IN_PATH, "r", encoding="utf-8"))
    baseline = data["variants"]["all_controls"]
    lines = [
        "# Ablation Report",
        "",
        f"Runs per variant: {data['runs_per_variant']} (seed={data['seed']})",
        "",
        "| Variant | WSR | Avg Latency (s) | p95 Latency (s) | ΔWSR vs all_controls | Δp95 vs all_controls (s) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, vals in data["variants"].items():
        if name == "all_controls":
            d_wsr = 0.0
            d_p95 = 0.0
        else:
            d_wsr = data["ablation_sensitivity"][name]["delta_wsr_vs_all_controls"]
            d_p95 = data["ablation_sensitivity"][name]["delta_p95_latency_s_vs_all_controls"]
        lines.append(f"| {name} | {vals['wsr']:.4f} | {vals['avg_latency_s']:.4f} | {vals['p95_latency_s']:.4f} | {d_wsr:.4f} | {d_p95:.4f} |")

    if baseline["wsr"] > 0:
        lines += ["", "Interpretation:", "- Circuit breaker and deadline controls should reduce failure cascades under stress scenarios."]

    with open(OUT_PATH, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")

    print("Wrote", OUT_PATH)


if __name__ == "__main__":
    main()
