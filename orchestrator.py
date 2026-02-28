"""
Main scan loop: create ephemeral Queue + Dict, pull from queue, dedup, spawn
investigators, enforce limits; then build graph and persist by scan_id.
"""

import queue as stdlib_queue
import time
from typing import Any

import modal

from app import app, image, osint_secret
from graph import NODE_PREFIX, SEEN_PREFIX, build_from_dict
from models import Entity, EntityType, ScanConfig, ScanStatus
from stream import write_stream_event


def _entity_key(etype: str, value: str) -> str:
    v = (value or "").strip().lower()
    if etype == EntityType.EMAIL.value:
        v = v.lower()
    return f"{etype}:{v}"


@app.function(image=image, secrets=[osint_secret])
def run_scan(scan_id: str, seed_entity: dict[str, Any], config_dict: dict[str, Any]) -> None:
    """
    Run one scan: ephemeral Queue + Dict, loop get_many -> dedup -> spawn
    resolvers, then write result to persistent Dict keyed by scan_id.
    """
    from resolvers import username as username_resolver
    from resolvers import email as email_resolver
    from resolvers import domain as domain_resolver
    from resolvers import username_enum as username_enum_resolver
    from resolvers import github_deep as github_deep_resolver
    from resolvers import breach as breach_resolver
    from resolvers import social as social_resolver

    config = ScanConfig.model_validate(config_dict)
    seed = Entity.model_validate(seed_entity)
    timeout_seconds = config.timeout_minutes * 60
    start = time.monotonic()
    seen_count = 0
    max_depth_reached = 0

    # Persistent Dict for this app to store results
    scan_results = modal.Dict.from_name("osint-scan-results", create_if_missing=True)

    write_stream_event(scan_id, "status", {
        "status": ScanStatus.RUNNING.value,
        "entities_seen": 0,
        "depth_reached": 0,
    })

    try:
        with modal.Queue.ephemeral() as q, modal.Dict.ephemeral() as d:
            # Seed node so graph has a root; resolvers add edges from "seed" to first resolved node
            seed_node: dict[str, Any] = {
                "id": "seed",
                "type": seed.type.value,
                "value": seed.value,
                "metadata": {"seed": True},
                "depth": 0,
            }
            d[f"{NODE_PREFIX}seed"] = seed_node
            d[f"{SEEN_PREFIX}seed"] = True  # don't process "seed" as a queue item
            write_stream_event(scan_id, "node", seed_node)
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

                    # Route to resolver by entity type
                    source_entity_key = item.get("parent_key") or "seed"
                    if etype == EntityType.USERNAME.value:
                        # Spawn GitHub resolver + deep GitHub + username enumeration + social
                        ref = username_resolver.resolve_github.spawn(
                            value, etype, depth, source_entity_key, q, d, scan_id
                        )
                        spawn_refs.append(ref)
                        for fn in (
                            github_deep_resolver.resolve_github_deep,
                            username_enum_resolver.enumerate_username,
                            social_resolver.resolve_social,
                        ):
                            ref = fn.spawn(value, etype, depth, source_entity_key, q, d, scan_id)
                            spawn_refs.append(ref)
                    elif etype == EntityType.EMAIL.value:
                        ref = email_resolver.resolve_email.spawn(
                            value, etype, depth, source_entity_key, q, d, scan_id
                        )
                        spawn_refs.append(ref)
                        ref2 = breach_resolver.resolve_breach.spawn(
                            value, etype, depth, source_entity_key, q, d, scan_id
                        )
                        spawn_refs.append(ref2)
                    elif etype == EntityType.DOMAIN.value:
                        ref = domain_resolver.resolve_domain.spawn(
                            value, etype, depth, source_entity_key, q, d, scan_id
                        )
                        spawn_refs.append(ref)

            # Wait for all spawned resolvers before snapshotting the graph
            for ref in spawn_refs:
                try:
                    ref.get()
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

            scan_results[scan_id] = {
                "status": ScanStatus.COMPLETED.value,
                "graph": graph_payload,
                "error": None,
                "entities_seen": seen_count,
                "depth_reached": max_depth_reached,
            }
            write_stream_event(scan_id, "status", {
                "status": ScanStatus.COMPLETED.value,
                "entities_seen": seen_count,
                "depth_reached": max_depth_reached,
                "error": None,
            })
    except Exception as e:
        scan_results[scan_id] = {
            "status": ScanStatus.FAILED.value,
            "graph": None,
            "error": str(e),
            "entities_seen": seen_count,
            "depth_reached": max_depth_reached,
        }
        write_stream_event(scan_id, "status", {
            "status": ScanStatus.FAILED.value,
            "entities_seen": seen_count,
            "depth_reached": max_depth_reached,
            "error": str(e),
        })
