"""FastAPI endpoints: POST /scan, GET /scan/{id}/status, GET /scan/{id}/graph, GET /scan/{id}/events, GET /scan/{id}/log, GET /debug/{id}."""

import uuid
from typing import Any

import modal

from app import app, image, osint_secret
from graph import build_from_dict
from models import GraphResponse, ScanConfig, ScanRequest, ScanResponse, ScanStatus, StatusResponse
from scan_log import load_activity_log

# Persistent Dict for scan results (same name as in orchestrator)
SCAN_RESULTS_DICT = "osint-scan-results"
_STREAM_PREFIX = "osint-stream-"


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=100)
@modal.asgi_app()
def fastapi_app() -> Any:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware

    from orchestrator import run_scan

    web_app = FastAPI(title="OSINT Recon API")

    web_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    scan_results = modal.Dict.from_name(SCAN_RESULTS_DICT, create_if_missing=True)

    @web_app.post("/scan", response_model=ScanResponse)
    def post_scan(req: ScanRequest) -> ScanResponse:
        scan_id = str(uuid.uuid4())
        config = (req.config or ScanConfig()).model_dump()
        seed_entity = req.seed.model_dump(mode="json")
        email = req.seed.email
        scan_results[scan_id] = {
            "status": ScanStatus.RUNNING.value,
            "graph": None,
            "error": None,
            "entities_seen": 1,
            "depth_reached": 0,
        }
        run_scan.spawn(scan_id, seed_entity, config, email)
        return ScanResponse(scan_id=scan_id)

    @web_app.get("/scan/{scan_id}/status", response_model=StatusResponse)
    def get_scan_status(scan_id: str) -> StatusResponse:
        if scan_id not in scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")
        row = scan_results[scan_id]
        return StatusResponse(
            scan_id=scan_id,
            status=ScanStatus(row["status"]),
            entities_seen=row.get("entities_seen", 0),
            depth_reached=row.get("depth_reached", 0),
            error=row.get("error"),
            report=row.get("report"),
        )

    @web_app.post("/scan/{scan_id}/stop")
    def post_scan_stop(scan_id: str):
        """Signal the running scan to stop. Idempotent."""
        if scan_id not in scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")
        row = scan_results[scan_id]
        if row["status"] != ScanStatus.RUNNING.value:
            return {"ok": True, "already_stopped": True}
        d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
        d["stop"] = True
        return {"ok": True}

    @web_app.get("/scan/{scan_id}/graph", response_model=GraphResponse)
    def get_scan_graph(scan_id: str) -> GraphResponse:
        if scan_id not in scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")
        row = scan_results[scan_id]
        if row["status"] == ScanStatus.FAILED.value:
            raise HTTPException(status_code=503, detail=row.get("error") or "Scan failed")
        graph = row.get("graph")
        if not graph and row["status"] == ScanStatus.RUNNING.value:
            try:
                d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=False)
                snapshot = {k: d[k] for k in d.keys()}
                graph = build_from_dict(snapshot)
            except Exception:
                graph = None
        if not graph:
            return GraphResponse(nodes=[], edges=[])
        return GraphResponse(nodes=graph.get("nodes", []), edges=graph.get("edges", []))

    @web_app.get("/scan/{scan_id}/graph/download")
    def download_scan_graph(scan_id: str):
        """Return the completed graph as a downloadable JSON file."""
        import json as _json
        from fastapi.responses import Response

        if scan_id not in scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")
        row = scan_results[scan_id]
        graph = row.get("graph") or {}
        content = _json.dumps(
            {
                "scan_id": scan_id,
                "nodes": graph.get("nodes", []),
                "edges": graph.get("edges", []),
                "report": row.get("report"),
            },
            indent=2,
        )
        filename = f"phantom-{scan_id[:8]}.json"
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @web_app.get("/scan/{scan_id}/report")
    def get_scan_report(scan_id: str):
        """Return the final intelligence report for a completed scan."""
        from fastapi.responses import Response

        if scan_id not in scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")
        row = scan_results[scan_id]
        report = row.get("report")
        if report is None:
            status = row.get("status", "")
            if status == ScanStatus.RUNNING.value:
                raise HTTPException(status_code=202, detail="Scan still running; report not yet available.")
            raise HTTPException(status_code=404, detail="Report not available for this scan.")
        return Response(
            content=report,
            media_type="text/plain; charset=utf-8",
        )

    @web_app.get("/scan/{scan_id}/events")
    def poll_events(scan_id: str, after: int = -1) -> dict:
        """
        Polling endpoint — returns all events with seq > after as a JSON array.
        Clients call this repeatedly (e.g. every second) instead of holding a
        long-lived SSE connection, avoiding Modal's 150-second request timeout.

        Response shape:
          {
            "events":   [...],   # list of event dicts with seq > after, sorted by seq
            "terminal": bool,    # true when the scan has reached a final state
            "status":   {...}    # terminal status payload (only set when terminal=true)
          }
        """
        if scan_id not in scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Collect all events with seq > after
        new_events: list[dict[str, Any]] = []
        try:
            sd = modal.Dict.from_name(
                f"{_STREAM_PREFIX}{scan_id}", create_if_missing=True
            )
            for k in sd.keys():
                if k.startswith("evt_"):
                    evt = sd.get(k)
                    if evt is not None and evt.get("seq", 0) > after:
                        new_events.append(evt)
        except Exception:
            pass

        new_events.sort(key=lambda e: e.get("seq", 0))

        # Check scan status
        try:
            row = scan_results.get(scan_id)
        except Exception:
            row = None

        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan_status = row.get("status", "running")
        terminal = scan_status in (
            ScanStatus.COMPLETED.value,
            ScanStatus.FAILED.value,
            ScanStatus.CANCELLED.value,
        )

        status_payload: dict[str, Any] | None = None
        if terminal:
            status_payload = {
                "status": scan_status,
                "entities_seen": row.get("entities_seen", 0),
                "depth_reached": row.get("depth_reached", 0),
                "error": row.get("error"),
            }

        return {
            "events": new_events,
            "terminal": terminal,
            "status": status_payload,
        }


    @web_app.get("/debug/{scan_id}")
    def debug_scan(scan_id: str):
        """Enhanced debug: activity log, resolver summary, entity flow, queue depth, timeline."""
        if scan_id not in scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")

        activity_log = load_activity_log(scan_id)

        # Resolver summary: aggregate resolver_spawned, resolver_completed, resolver_failed
        resolver_stats: dict[str, dict[str, Any]] = {}
        for evt in activity_log:
            resolver = evt.get("resolver")
            if resolver is None:
                continue
            if resolver not in resolver_stats:
                resolver_stats[resolver] = {"calls": 0, "successes": 0, "failures": 0, "durations": []}
            if evt.get("event_type") == "resolver_spawned":
                resolver_stats[resolver]["calls"] += 1
            elif evt.get("event_type") == "resolver_completed":
                resolver_stats[resolver]["successes"] += 1
                dur = evt.get("duration")
                if dur is not None:
                    resolver_stats[resolver]["durations"].append(dur * 1000)
            elif evt.get("event_type") == "resolver_failed":
                resolver_stats[resolver]["failures"] += 1

        resolver_summary = [
            {
                "resolver": r,
                "calls": s["calls"],
                "successes": s["successes"],
                "failures": s["failures"],
                "avg_duration_ms": round(sum(s["durations"]) / len(s["durations"]), 2) if s["durations"] else 0.0,
            }
            for r, s in sorted(resolver_stats.items())
        ]

        # Entity flow: count entity_skipped by reason, processed, discovered
        skipped: dict[str, int] = {"dedup": 0, "depth_limit": 0, "max_entities": 0, "blocklist": 0}
        for evt in activity_log:
            if evt.get("event_type") == "entity_skipped":
                reason = evt.get("reason", "")
                if reason in skipped:
                    skipped[reason] += 1

        processed = sum(1 for e in activity_log if e.get("event_type") == "resolver_spawned")
        row = scan_results.get(scan_id) or {}
        discovered = row.get("entities_seen", 0)

        status = row.get("status", "unknown")
        if status in (ScanStatus.COMPLETED.value, ScanStatus.FAILED.value, ScanStatus.CANCELLED.value):
            estimated_remaining = "Scan completed"
        else:
            estimated_remaining = "Agent loop running"

        # Timeline for Gantt: ts, event_type, resolver?, duration?
        timeline = [
            {
                "ts": e.get("ts"),
                "event_type": e.get("event_type"),
                "resolver": e.get("resolver"),
                "duration": e.get("duration"),
                "node_id": e.get("node_id"),
            }
            for e in activity_log
        ]

        return {
            "scan_id": scan_id,
            "status": status,
            "activity_log": activity_log,
            "resolver_summary": resolver_summary,
            "entity_flow": {
                "discovered": discovered,
                "skipped": skipped,
                "processed": processed,
            },
            "estimated_remaining": estimated_remaining,
            "timeline": timeline,
        }

    @web_app.get("/scan/{scan_id}/telemetry")
    def get_scan_telemetry(scan_id: str):
        """Return the telemetry bundle as downloadable JSON."""
        import json as _json
        from fastapi.responses import Response

        from telemetry.exporter import TELEMETRY_DICT_NAME

        telemetry_dict = modal.Dict.from_name(TELEMETRY_DICT_NAME, create_if_missing=True)
        try:
            bundle = telemetry_dict[scan_id]
        except KeyError:
            raise HTTPException(status_code=404, detail="Telemetry not found for this scan")
        content = _json.dumps(bundle, indent=2, default=str)
        filename = f"telemetry-{scan_id[:8]}.json"
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @web_app.get("/scan/{scan_id}/evaluation")
    def get_scan_evaluation(scan_id: str):
        """Return (or generate) the evaluation scorecard for a completed scan."""
        from telemetry.evaluator import EVAL_DICT_NAME, evaluate_bundle
        from telemetry.exporter import TELEMETRY_DICT_NAME

        eval_dict = modal.Dict.from_name(EVAL_DICT_NAME, create_if_missing=True)

        try:
            cached = eval_dict[scan_id]
            return cached
        except KeyError:
            pass

        telemetry_dict = modal.Dict.from_name(TELEMETRY_DICT_NAME, create_if_missing=True)
        try:
            bundle = telemetry_dict[scan_id]
        except KeyError:
            raise HTTPException(status_code=404, detail="Telemetry not found for this scan")

        status = bundle.get("final_status")
        if status is None:
            raise HTTPException(status_code=409, detail="Scan still running; evaluation requires a completed scan")

        try:
            scorecard = evaluate_bundle(bundle)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Evaluation failed: {exc}")

        try:
            eval_dict[scan_id] = scorecard
        except Exception:
            pass

        return scorecard

    @web_app.get("/telemetry/proposals")
    def get_proposals(last_n: int = 10):
        """Return (or generate) improvement proposals derived from the last N
        evaluation scorecards.  Requires at least 3 evaluated scans."""
        from telemetry.proposer import generate_proposals

        try:
            result = generate_proposals(last_n=last_n)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            raise HTTPException(
                status_code=502, detail=f"Proposal generation failed: {exc}"
            )
        return result

    @web_app.get("/telemetry/manifest")
    def get_manifest():
        """Return the agent manifest — a self-describing document containing
        the project structure, current prompt texts, tool schemas, and the
        latest improvement proposals.

        External AI agents (OpenClaw, Cursor agents) should fetch this
        endpoint first to understand the stable contract before consuming
        proposals or submitting webhook callbacks.
        """
        from telemetry.manifest import generate_manifest

        try:
            return generate_manifest()
        except Exception as exc:
            raise HTTPException(
                status_code=502, detail=f"Manifest generation failed: {exc}"
            )

    @web_app.post("/telemetry/webhook")
    def post_webhook(payload: dict):
        """Accept a completed-change report from an external agent.

        Request body (all fields required unless marked optional):
          {
            "agent_id":              str    — identifier of the submitting agent,
            "proposal_target_file":  str    — file the agent targeted,
            "proposal_section":      str    — section / constant name changed,
            "patch_description":     str    — human-readable description of the patch,
            "result":                str    — "success" | "failure" | "partial",
            "details":               str?   — optional extra context / error message,
            "applied_at":            float? — unix timestamp when change was applied
          }

        The submission is logged to the ``osint-agent-webhooks`` Modal Dict
        (keyed by a fresh UUID) and will be visible to the next evaluation
        cycle.

        Returns:
          { "ok": true, "logged_id": "<uuid>" }
        """
        import time as _time
        import uuid as _uuid

        from telemetry.manifest import WEBHOOK_DICT_NAME, WebhookPayload, WebhookResponse

        try:
            validated = WebhookPayload.model_validate(payload)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Invalid payload: {exc}")

        logged_id = str(_uuid.uuid4())
        entry = {
            **validated.model_dump(),
            "received_at": _time.time(),
            "logged_id": logged_id,
        }

        try:
            webhook_dict = modal.Dict.from_name(WEBHOOK_DICT_NAME, create_if_missing=True)
            webhook_dict[logged_id] = entry
        except Exception as exc:
            raise HTTPException(
                status_code=502, detail=f"Failed to log webhook submission: {exc}"
            )

        return WebhookResponse(ok=True, logged_id=logged_id)

    @web_app.get("/telemetry/changelog")
    def get_changelog_endpoint(limit: int = 50, target_file: str | None = None):
        """Return changelog entries recording applied prompt/config changes.

        Query params:
          limit       — max entries to return (default 50, newest first)
          target_file — filter to a specific file (e.g. agent/planner.py)
        """
        from telemetry.changelog import get_changelog

        return get_changelog(limit=limit, target_file=target_file)

    @web_app.post("/telemetry/changelog/rollback/{entry_id}")
    def rollback_changelog_entry(entry_id: str):
        """Roll back a previously applied change.

        Marks the changelog entry as rolled back and returns the
        ``content_before`` text so the calling agent can re-apply it and
        redeploy.

        Response shape:
          {
            "entry":             {...},   # updated changelog entry
            "restored_content":  "...",  # the content to restore
            "target_file":       "...",
            "section":           "..."
          }
        """
        from telemetry.changelog import rollback_change

        try:
            result = rollback_change(entry_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Rollback failed: {exc}")
        return result

    @web_app.get("/scan/{scan_id}/log")
    def get_scan_log(
        scan_id: str,
        resolver: str | None = None,
        status: str | None = None,
        event_type: str | None = None,
    ):
        """Return activity log as JSON array. Optional filters: ?resolver=... &status=... &event_type=..."""
        if scan_id not in scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")

        events = load_activity_log(scan_id)

        if resolver:
            events = [e for e in events if e.get("resolver") == resolver]
        if status:
            # status=completed -> resolver_completed, gpu_extraction_completed, scan_finalized (completed)
            # status=failed -> resolver_failed, gpu_extraction_failed
            status_lower = status.lower()
            if status_lower == "completed":
                events = [e for e in events if e.get("event_type") in ("resolver_completed", "gpu_extraction_completed")]
            elif status_lower == "failed":
                events = [e for e in events if e.get("event_type") in ("resolver_failed", "gpu_extraction_failed")]
            elif status_lower in ("running", "cancelled"):
                events = [e for e in events if e.get("event_type") == "scan_finalized" and e.get("status") == status_lower]
        if event_type:
            events = [e for e in events if e.get("event_type") == event_type]

        return {"scan_id": scan_id, "events": events}

    return web_app
