from __future__ import annotations

from typing import Any, Dict, List


def _has_keys(obj: Dict[str, Any], keys: List[str]) -> bool:
    return all(k in obj for k in keys)


def validate_call(tool_name: str, payload: Dict[str, Any], response: Dict[str, Any]) -> bool:
    if tool_name == "itsm.get_incident":
        return _has_keys(payload, ["incident_id"]) and _has_keys(
            response, ["incident_id", "severity", "status", "summary", "details"]
        )

    if tool_name == "data.run_sql":
        return _has_keys(payload, ["query", "purpose", "evidence_id"]) and _has_keys(
            response, ["rows", "row_count", "execution_ms", "result_fingerprint", "evidence_ref"]
        ) and int(response.get("row_count", -1)) == len(response.get("rows", []))

    if tool_name == "logs.search":
        return _has_keys(payload, ["query", "time_range", "evidence_id"]) and _has_keys(
            response, ["hits", "hit_count", "search_ms", "evidence_ref"]
        ) and int(response.get("hit_count", -1)) == len(response.get("hits", []))

    if tool_name == "grc.classify_and_redact":
        return _has_keys(payload, ["text", "policy"]) and _has_keys(
            response, ["redacted_text", "pii_found", "tags", "confidence"]
        ) and 0.0 <= float(response.get("confidence", -1)) <= 1.0

    if tool_name == "comms.send_update":
        return _has_keys(payload, ["channel", "message", "idempotency_key"]) and _has_keys(
            response, ["message_id", "sent_ms"]
        )

    return False
