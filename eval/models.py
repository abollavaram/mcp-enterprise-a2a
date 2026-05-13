from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RunResult:
    scenario_id: str
    success: bool
    latency_s: float
    est_cost_usd: float
    avr: float
    ecr: float
    pcr: float
    notes: str


class ToolError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
