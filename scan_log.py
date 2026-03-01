"""Per-scan activity log — persists timestamped events to a named Modal Dict.

Event schema (canonical event_type and typical kwargs):

  scan_started       — seed_entity, config
  resolver_spawned   — resolver, entity_key, depth
  resolver_completed — resolver, entity_key, duration, nodes_found, edges_found
  resolver_failed    — resolver, entity_key, error; optional: service, response_preview, timeout
  entity_skipped     — reason (dedup | depth_limit | max_entities | blocklist), entity_key
  gpu_extraction_started  — node_id
  gpu_extraction_completed — node_id, nodes_found, edges_found
  gpu_extraction_failed    — node_id, error
  gpu_extraction_error    — error (best-effort GPU phase failure)
  queue_drained      — (no extra kwargs)
  queue_get_failed   — error
  scan_timeout       — timeout_seconds, pending_resolvers
  scan_finalized     — status, entities_seen, depth_reached
  dict_put_failed    — error, key, data_preview
  dict_get_failed    — error, key
  queue_put_failed   — error, data_preview
  scan_results_put_failed — error, data_preview

Every event dict also has: ts (float), seq (int), event_type (str).
"""

import time
import uuid
from typing import Any

import modal

_LOG_PREFIX = "osint-log-"
_KEY_PREFIX = "log_"


def log_scan_event(scan_id: str, event_type: str, **kwargs: Any) -> None:
    """
    Append a timestamped event to the per-scan activity log.

    Best-effort; failures are silently swallowed.
    Keys use seq+uuid so concurrent writes never collide.
    """
    if not scan_id:
        return
    try:
        ld = modal.Dict.from_name(f"{_LOG_PREFIX}{scan_id}", create_if_missing=True)
        seq: int = ld.get("next_seq", 0)
        ld["next_seq"] = seq + 1
        ts = time.time()
        event = {
            "ts": ts,
            "seq": seq,
            "event_type": event_type,
            **kwargs,
        }
        ld[f"{_KEY_PREFIX}{seq}_{uuid.uuid4().hex}"] = event
    except Exception:
        pass  # activity log is best-effort


def load_activity_log(scan_id: str) -> list[dict[str, Any]]:
    """
    Load all activity log events for a scan, sorted chronologically by ts.
    Returns empty list if scan_id is empty or Dict is missing/empty.
    """
    if not scan_id:
        return []
    try:
        ld = modal.Dict.from_name(f"{_LOG_PREFIX}{scan_id}", create_if_missing=True)
        events: list[dict[str, Any]] = []
        for k in ld.keys():
            if k.startswith(_KEY_PREFIX) and k != "next_seq":
                evt = ld.get(k)
                if evt is not None and isinstance(evt, dict):
                    events.append(evt)
        events.sort(key=lambda e: (e.get("ts", 0), e.get("seq", 0)))
        return events
    except Exception:
        return []
