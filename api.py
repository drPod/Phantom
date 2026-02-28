"""FastAPI endpoints: POST /scan, GET /scan/{id}/status, GET /scan/{id}/graph, GET /scan/{id}/stream."""

import asyncio
import json
import time
import uuid
from typing import Any

import modal

from app import app, image, osint_secret
from models import GraphResponse, ScanConfig, ScanRequest, ScanResponse, ScanStatus, StatusResponse

# Persistent Dict for scan results (same name as in orchestrator)
SCAN_RESULTS_DICT = "osint-scan-results"
_STREAM_PREFIX = "osint-stream-"


@app.function(image=image, secrets=[osint_secret])
@modal.asgi_app()
def fastapi_app() -> Any:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import StreamingResponse

    from orchestrator import run_scan

    web_app = FastAPI(title="OSINT Recon API")

    web_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    scan_results = modal.Dict.from_name(SCAN_RESULTS_DICT, create_if_missing=True)

    @web_app.post("/scan", response_model=ScanResponse)
    def post_scan(req: ScanRequest) -> ScanResponse:
        scan_id = str(uuid.uuid4())
        config = (req.config or ScanConfig()).model_dump()
        seed_entity = req.seed.model_dump(mode="json")
        scan_results[scan_id] = {
            "status": ScanStatus.RUNNING.value,
            "graph": None,
            "error": None,
            "entities_seen": 0,
            "depth_reached": 0,
        }
        run_scan.spawn(scan_id, seed_entity, config)
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
        if row["status"] == ScanStatus.RUNNING.value:
            raise HTTPException(status_code=202, detail="Scan still running")
        if row["status"] == ScanStatus.FAILED.value:
            raise HTTPException(status_code=503, detail=row.get("error") or "Scan failed")
        # CANCELLED and COMPLETED both return the graph (possibly partial)
        graph = row.get("graph")
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
        if row["status"] == ScanStatus.RUNNING.value:
            raise HTTPException(status_code=202, detail="Scan still running")
        # CANCELLED and COMPLETED both allow download
        graph = row.get("graph") or {}
        content = _json.dumps(
            {
                "scan_id": scan_id,
                "nodes": graph.get("nodes", []),
                "edges": graph.get("edges", []),
            },
            indent=2,
        )
        filename = f"phantom-{scan_id[:8]}.json"
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @web_app.get("/scan/{scan_id}/stream")
    async def stream_scan(scan_id: str) -> StreamingResponse:
        """
        SSE endpoint — polls the per-scan stream Dict every 0.5 s and yields
        new events as  data: <json>\n\n  until the scan finishes.
        """
        async def event_generator():
            seen_keys: set[str] = set()

            while True:
                # ── collect new events ──────────────────────────────────────
                new_events: list[dict[str, Any]] = []
                try:
                    sd = modal.Dict.from_name(
                        f"{_STREAM_PREFIX}{scan_id}", create_if_missing=True
                    )
                    for k in sd.keys():
                        if k.startswith("evt_") and k not in seen_keys:
                            evt = sd.get(k)
                            if evt is not None:
                                seen_keys.add(k)
                                new_events.append(evt)
                except Exception:
                    pass

                # yield events sorted by sequence number
                new_events.sort(key=lambda e: e.get("seq", 0))
                for evt in new_events:
                    yield f"data: {json.dumps(evt)}\n\n"

                # ── check scan status ────────────────────────────────────────
                try:
                    row = scan_results.get(scan_id)
                except Exception:
                    row = None

                if row is None:
                    yield (
                        f"data: {json.dumps({'type': 'error', 'payload': {'message': 'Scan not found'}})}\n\n"
                    )
                    return

                status = row.get("status", "running")
                if status in (ScanStatus.COMPLETED.value, ScanStatus.FAILED.value, ScanStatus.CANCELLED.value):
                    # Drain any remaining events one last time
                    final_events: list[dict[str, Any]] = []
                    try:
                        sd = modal.Dict.from_name(
                            f"{_STREAM_PREFIX}{scan_id}", create_if_missing=True
                        )
                        for k in sd.keys():
                            if k.startswith("evt_") and k not in seen_keys:
                                evt = sd.get(k)
                                if evt is not None:
                                    seen_keys.add(k)
                                    final_events.append(evt)
                    except Exception:
                        pass
                    final_events.sort(key=lambda e: e.get("seq", 0))
                    for evt in final_events:
                        yield f"data: {json.dumps(evt)}\n\n"

                    # Terminal status event
                    terminal = {
                        "seq": -1,
                        "type": "status",
                        "payload": {
                            "status": status,
                            "entities_seen": row.get("entities_seen", 0),
                            "depth_reached": row.get("depth_reached", 0),
                            "error": row.get("error"),
                        },
                        "ts": time.time(),
                    }
                    yield f"data: {json.dumps(terminal)}\n\n"
                    return

                await asyncio.sleep(0.5)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )


    @web_app.get("/debug/{scan_id}")
    def debug_scan(scan_id: str):
        """Return raw dict contents for debugging a stuck scan."""
        out = {}
        try:
            sr = modal.Dict.from_name("osint-scan-results", create_if_missing=True)
            out["scan_results"] = dict(sr.get(scan_id, {}))
        except Exception as e:
            out["scan_results_error"] = str(e)
        try:
            d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
            keys = list(d.keys())
            out["dict_keys"] = keys
            out["dict_key_count"] = len(keys)
        except Exception as e:
            out["dict_error"] = str(e)
        try:
            q = modal.Queue.from_name(f"osint-q-{scan_id}", create_if_missing=True)
            out["queue_info"] = "ok"
        except Exception as e:
            out["queue_error"] = str(e)
        return out

    return web_app
