"""FastAPI endpoints: POST /scan, GET /scan/{id}/status, GET /scan/{id}/graph."""

import uuid
from typing import Any

import modal

from app import app, image, osint_secret
from models import GraphResponse, ScanConfig, ScanRequest, ScanResponse, ScanStatus, StatusResponse

# Persistent Dict for scan results (same name as in orchestrator)
SCAN_RESULTS_DICT = "osint-scan-results"


@app.function(image=image, secrets=[osint_secret])
@modal.asgi_app()
def fastapi_app() -> Any:
    from fastapi import FastAPI, HTTPException

    from orchestrator import run_scan

    web_app = FastAPI(title="OSINT Recon API")
    scan_results = modal.Dict.from_name(SCAN_RESULTS_DICT, create_if_missing=True)

    @web_app.post("/scan", response_model=ScanResponse)
    def post_scan(req: ScanRequest) -> ScanResponse:
        scan_id = str(uuid.uuid4())
        config = (req.config or ScanConfig()).model_dump()
        seed_entity = req.seed.model_dump()
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

    @web_app.get("/scan/{scan_id}/graph", response_model=GraphResponse)
    def get_scan_graph(scan_id: str) -> GraphResponse:
        if scan_id not in scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")
        row = scan_results[scan_id]
        if row["status"] == ScanStatus.RUNNING.value:
            raise HTTPException(status_code=202, detail="Scan still running")
        if row["status"] == ScanStatus.FAILED.value:
            raise HTTPException(status_code=503, detail=row.get("error") or "Scan failed")
        graph = row.get("graph")
        if not graph:
            return GraphResponse(nodes=[], edges=[])
        return GraphResponse(nodes=graph.get("nodes", []), edges=graph.get("edges", []))

    return web_app
