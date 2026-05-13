from __future__ import annotations

import time
from typing import Any, Callable, Dict, Tuple

from models import ToolError


def now_ms() -> int:
    return int(time.time() * 1000)


def call_with_controls(
    tool_name: str,
    payload: Dict[str, Any],
    deadline_ms: int,
    controls: Dict[str, Any],
    breaker_state: Dict[str, Dict[str, Any]],
    call_impl: Callable[[str, Dict[str, Any]], Tuple[Dict[str, Any], float]],
) -> Dict[str, Any]:
    retries_enabled = bool(controls.get("retries_enabled", True))
    breaker_enabled = bool(controls.get("circuit_breaker_enabled", True))
    deadline_enabled = bool(controls.get("deadline_propagation_enabled", True))

    threshold = int(controls.get("circuit_breaker_fail_threshold", 2))
    open_ms = int(controls.get("circuit_breaker_open_ms", 500))

    if breaker_enabled:
        st = breaker_state.setdefault(tool_name, {"fails": 0, "open_until_ms": 0})
        if now_ms() < int(st["open_until_ms"]):
            raise ToolError("UPSTREAM_DOWN", f"circuit open for {tool_name}")

    attempt = 0
    max_attempts = int(controls.get("max_attempts", 3)) if retries_enabled else 1
    backoff_ms = int(controls.get("initial_backoff_ms", 50))

    while True:
        attempt += 1
        if deadline_enabled and (now_ms() > deadline_ms):
            raise ToolError("UPSTREAM_TIMEOUT", f"deadline exceeded before calling {tool_name}")
        try:
            resp, _ = call_impl(tool_name, payload)
            if breaker_enabled:
                breaker_state.setdefault(tool_name, {"fails": 0, "open_until_ms": 0})["fails"] = 0
            return resp
        except ToolError as e:
            if breaker_enabled:
                st = breaker_state.setdefault(tool_name, {"fails": 0, "open_until_ms": 0})
                st["fails"] = int(st["fails"]) + 1
                if st["fails"] >= threshold:
                    st["open_until_ms"] = now_ms() + open_ms

            retryable = e.code in {"UPSTREAM_TIMEOUT", "UPSTREAM_DOWN", "RATE_LIMIT"}
            if (not retries_enabled) or (not retryable) or (attempt >= max_attempts):
                raise
            if deadline_enabled and (now_ms() + backoff_ms > deadline_ms):
                raise ToolError("UPSTREAM_TIMEOUT", f"deadline exceeded during backoff for {tool_name}")
            time.sleep(backoff_ms / 1000.0)
            backoff_ms *= 2
