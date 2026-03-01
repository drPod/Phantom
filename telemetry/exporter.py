"""Telemetry bundle exporter — incrementally collects scan telemetry and
flushes to a Modal Dict so an external AI agent can later evaluate prompts
and workflow.

Every ``record_*`` call appends to the in-memory bundle and immediately
flushes the full bundle to the shared ``osint-telemetry`` Modal Dict keyed
by ``scan_id``.  This ensures the latest state survives process kills.

All writes are best-effort: exceptions are swallowed so telemetry never
breaks a running scan.
"""

import time
from typing import Any

import modal

TELEMETRY_DICT_NAME = "osint-telemetry"


class TelemetryCollector:
    """Accumulates telemetry events for a single scan and persists them
    incrementally to a Modal Dict."""

    def __init__(self, scan_id: str, seed_entity: dict[str, Any], config: dict[str, Any]) -> None:
        self._scan_id = scan_id
        self._bundle: dict[str, Any] = {
            "scan_id": scan_id,
            "seed_entity": seed_entity,
            "config": config,
            "started_at": time.time(),
            "finished_at": None,
            "final_status": None,
            "planner_turns": [],
            "analyst_briefs": [],
            "resolvers": [],
            "graph_summary": None,
            "report": None,
            "errors": [],
            "user_stopped": False,
        }
        self._flush()

    # ------------------------------------------------------------------
    # Recording helpers
    # ------------------------------------------------------------------

    def record_planner_turn(
        self,
        turn: int,
        reasoning: str | None,
        tool_calls: list[dict[str, Any]],
        stop_reason: str | None,
    ) -> None:
        self._bundle["planner_turns"].append({
            "turn": turn,
            "ts": time.time(),
            "reasoning": reasoning,
            "tool_calls": tool_calls,
            "stop_reason": stop_reason,
        })
        self._flush()

    def record_analyst_brief(
        self,
        turn: int,
        brief: str,
        new_nodes: int,
        new_edges: int,
        background: bool = False,
    ) -> None:
        self._bundle["analyst_briefs"].append({
            "turn": turn,
            "ts": time.time(),
            "brief": brief,
            "new_nodes": new_nodes,
            "new_edges": new_edges,
            "background": background,
        })
        self._flush()

    def record_resolver(
        self,
        resolver_name: str,
        entity_key: str,
        succeeded: bool,
        error: str | None,
        duration_ms: float,
    ) -> None:
        self._bundle["resolvers"].append({
            "resolver_name": resolver_name,
            "entity_key": entity_key,
            "succeeded": succeeded,
            "error": error,
            "duration_ms": round(duration_ms, 1),
            "ts": time.time(),
        })
        self._flush()

    def record_error(self, message: str) -> None:
        self._bundle["errors"].append(message)
        self._flush()

    def record_user_stop(self) -> None:
        self._bundle["user_stopped"] = True
        self._flush()

    def finalize(
        self,
        status: str,
        graph_summary: dict[str, Any] | None,
        report: str | None,
    ) -> None:
        self._bundle["finished_at"] = time.time()
        self._bundle["final_status"] = status
        self._bundle["graph_summary"] = graph_summary
        self._bundle["report"] = report
        self._flush()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _flush(self) -> None:
        """Write the full bundle to the shared Modal Dict.  Best-effort."""
        try:
            d = modal.Dict.from_name(TELEMETRY_DICT_NAME, create_if_missing=True)
            d[self._scan_id] = self._bundle
        except Exception:
            pass
