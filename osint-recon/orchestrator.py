"""
Main scan loop: create ephemeral Queue + Dict, pull from queue, dedup, spawn
investigators, enforce limits; then build graph and persist by scan_id.
"""

import queue as stdlib_queue
import time
from typing import Any

import modal

from app import app, image, osint_secret
from graph import NODE_PREFIX, SEEN_PREFIX, build_from_dict, serialize_graph
from models import Entity, EntityType, ScanConfig, ScanStatus


def _entity_key(etype: str, value: str) -> str:
    v = (value or "").strip().lower()
    if etype == EntityType.EMAIL.value:
        v = v.lower()
    return f"{etype}:{v}"


@app.function(image=image, secrets=[osint_secret], mounts=[modal.Mount.from_local_dir(__file__.rsplit("/", 1)[0], remote_path="/root/osint_recon")])
def run_scan(scan_id: str, seed_entity: dict[str, Any], config_dict: dict[str, Any]) -> None:
    """
    Run one scan: ephemeral Queue + Dict, loop get_many -> dedup -> spawn
    resolvers, then write result to persistent Dict keyed by scan_id.
    """
    from resolvers import username as username_resolver

    config = ScanConfig.model_validate(config_dict)
    seed = Entity.model_validate(seed_entity)
    timeout_seconds = config.timeout_minutes * 60
    start = time.monotonic()
    seen_count = 0
    max_depth_reached = 0

    # Persistent Dict for this app to store results
    scan_results = modal.Dict.from_name("osint-scan-results", create_if_missing=True)

    try:
        with modal.Queue.ephemeral() as q, modal.Dict.ephemeral() as d:
            # Seed node so graph has a root; resolvers add edges from "seed" to first resolved node
            d[f"{NODE_PREFIX}seed"] = {
                "id": "seed",
                "type": seed.type.value,
                "value": seed.value,
                "metadata": {"seed": True},
                "depth": 0,
            }
            d[f"{SEEN_PREFIX}seed"] = True  # don't process "seed" as a queue item
            # First work item: the seed entity (depth 0)
            q.put({
                "type": seed.type.value,
                "value": seed.value,
                "source": "seed",
                "confidence": 1.0,
                "depth": 0,
            })

            batch_size = 50
            spawn_refs: list[Any] = []
            while True:
                if time.monotonic() - start >= timeout_seconds:
                    d["stop"] = True
                    break
                try:
                    items = q.get_many(batch_size, timeout=5)
                except stdlib_queue.Empty:
                    break
                if not items:
                    break

                for item in items:
                    if "stop" in d:
                        break
                    if seen_count >= config.max_entities:
                        d["stop"] = True
                        break
                    depth = item.get("depth", 0)
                    if depth > config.max_depth:
                        continue
                    max_depth_reached = max(max_depth_reached, depth)
                    etype = item.get("type", "")
                    value = (item.get("value") or "").strip()
                    if not value:
                        continue
                    key = _entity_key(etype, value)
                    seen_key = f"{SEEN_PREFIX}{key}"
                    if seen_key in d:
                        continue
                    d[seen_key] = True
                    seen_count += 1

                    # Route to resolver by type (Phase 1: username only)
                    source_entity_key = item.get("parent_key") or "seed"
                    if etype == EntityType.USERNAME.value:
                        ref = username_resolver.resolve_github.spawn(
                            value,
                            etype,
                            depth,
                            source_entity_key,
                            q,
                            d,
                        )
                        spawn_refs.append(ref)
                    # Phase 2: email, domain, ip, phone, wallet

            # Wait for all spawned resolvers (with timeout so one stuck resolver doesn't hang the scan)
            RESOLVER_WAIT_TIMEOUT = 120  # seconds per ref
            for ref in spawn_refs:
                try:
                    ref.get(timeout=RESOLVER_WAIT_TIMEOUT)
                except Exception:
                    pass

            # Collect graph from Dict: snapshot keys then build
            keys = list(d.keys())
            snapshot: dict[str, Any] = {}
            for k in keys:
                try:
                    snapshot[k] = d[k]
                except Exception:
                    pass
            graph_payload = build_from_dict(snapshot)
            graph_json = serialize_graph(graph_payload)

            scan_results[scan_id] = {
                "status": ScanStatus.COMPLETED.value,
                "graph": graph_payload,
                "error": None,
                "entities_seen": seen_count,
                "depth_reached": max_depth_reached,
            }
    except Exception as e:
        scan_results[scan_id] = {
            "status": ScanStatus.FAILED.value,
            "graph": None,
            "error": str(e),
            "entities_seen": seen_count,
            "depth_reached": max_depth_reached,
        }
