"""Real-time stream event writer — persists SSE events to a named Modal Dict."""

import time
import uuid
from typing import Any

import modal

_STREAM_PREFIX = "osint-stream-"


def write_stream_event(scan_id: str, event_type: str, payload: dict[str, Any]) -> None:
    """
    Write one SSE event to the persistent stream dict for scan_id.

    Keys use UUIDs so concurrent resolver calls never collide.
    next_seq is a best-effort monotonic counter (small gaps OK under concurrency).
    Events are best-effort: failures are silently swallowed.
    """
    if not scan_id:
        return
    try:
        sd = modal.Dict.from_name(f"{_STREAM_PREFIX}{scan_id}", create_if_missing=True)
        seq: int = sd.get("next_seq", 0)
        sd["next_seq"] = seq + 1
        sd[f"evt_{uuid.uuid4().hex}"] = {
            "seq": seq,
            "type": event_type,
            "payload": payload,
            "ts": time.time(),
        }
    except Exception:
        pass  # stream events are best-effort
