"""
Main scan loop: named Queue + Dict by scan_id, fan-out to resolvers, build graph.
"""

import time
import traceback
import uuid
from typing import Any

import modal

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX, SEEN_PREFIX, build_from_dict
from models import Entity, EntityType, ScanConfig, ScanStatus
from stream import write_stream_event


def _entity_key(etype: str, value: str) -> str:
    v = (value or "").strip().lower()
    return f"{etype}:{v}"


@app.function(image=image, secrets=[osint_secret], timeout=1200)
def run_scan(scan_id: str, seed_entity: dict[str, Any], config_dict: dict[str, Any]) -> None:
    """Fan-out scan: named Queue + Dict keyed by scan_id."""

    # Write to scan_results immediately so any crash is surfaced
    scan_results = modal.Dict.from_name("osint-scan-results", create_if_missing=True)
    scan_results[scan_id] = {
        "status": ScanStatus.RUNNING.value,
        "graph": None,
        "error": None,
        "entities_seen": 0,
        "depth_reached": 0,
    }

    try:
        # Import resolvers inside try so import errors are caught and reported
        from resolvers import username as username_resolver
        from resolvers import email as email_resolver
        from resolvers import domain as domain_resolver
        from resolvers import username_enum as username_enum_resolver
        from resolvers import github_deep as github_deep_resolver
        from resolvers import breach as breach_resolver
        from resolvers import social as social_resolver

        config = ScanConfig.model_validate(config_dict)
        seed = Entity.model_validate({**seed_entity, "source": seed_entity.get("source", "user"), "depth": seed_entity.get("depth", 0)})
        timeout_seconds = config.timeout_minutes * 60
        start = time.monotonic()
        seen_count = 0
        max_depth_reached = 0

        write_stream_event(scan_id, "status", {"status": ScanStatus.RUNNING.value, "entities_seen": 0})

        q = modal.Queue.from_name(f"osint-q-{scan_id}", create_if_missing=True)
        d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)

        seed_node: dict[str, Any] = {
            "id": "seed",
            "type": seed.type.value,
            "value": seed.value,
            "metadata": {"seed": True},
            "depth": 0,
        }
        d[f"{NODE_PREFIX}seed"] = seed_node
        d[f"{SEEN_PREFIX}seed"] = True
        write_stream_event(scan_id, "node", seed_node)

        q.put({
            "type": seed.type.value,
            "value": seed.value,
            "source": "seed",
            "confidence": 1.0,
            "depth": 0,
        })

        spawn_refs: list[Any] = []
        consecutive_empty = 0
        max_consecutive_empty = 4  # 4 * 15s = 60s quiet before done

        while True:
            if time.monotonic() - start >= timeout_seconds:
                d["stop"] = True
                break

            try:
                items = q.get_many(50, timeout=15)
            except Exception:
                items = []

            if not items:
                if not spawn_refs:
                    break
                consecutive_empty += 1
                if consecutive_empty >= max_consecutive_empty:
                    break
                continue

            consecutive_empty = 0

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

                # Update intermediate status
                scan_results[scan_id] = {
                    "status": ScanStatus.RUNNING.value,
                    "graph": None,
                    "error": None,
                    "entities_seen": seen_count,
                    "depth_reached": max_depth_reached,
                }

                source_entity_key = item.get("parent_key") or "seed"

                if etype == EntityType.USERNAME.value:
                    for fn in (
                        username_resolver.resolve_github,
                        github_deep_resolver.resolve_github_deep,
                        username_enum_resolver.enumerate_username,
                        social_resolver.resolve_social,
                    ):
                        spawn_refs.append(fn.spawn(value, etype, depth, source_entity_key, scan_id))

                elif etype == EntityType.EMAIL.value:
                    spawn_refs.append(email_resolver.resolve_email.spawn(value, etype, depth, source_entity_key, scan_id))
                    spawn_refs.append(breach_resolver.resolve_breach.spawn(value, etype, depth, source_entity_key, scan_id))

                elif etype == EntityType.DOMAIN.value:
                    spawn_refs.append(domain_resolver.resolve_domain.spawn(value, etype, depth, source_entity_key, scan_id))

            # If user requested stop, exit while after building partial graph
            if "stop" in d:
                for ref in spawn_refs:
                    try:
                        ref.get(timeout=120)
                    except Exception:
                        pass
                snapshot_stop: dict[str, Any] = {}
                for k in list(d.keys()):
                    try:
                        snapshot_stop[k] = d[k]
                    except Exception:
                        pass
                try:
                    from inference.extractor import EntityExtractor
                    extractor = EntityExtractor()
                    for k, v in list(snapshot_stop.items()):
                        if not k.startswith(NODE_PREFIX) or not isinstance(v, dict):
                            continue
                        meta = v.get("metadata", {}) or {}
                        node_value = v.get("value", "").strip().lower()
                        text_parts = []
                        for mval in meta.values():
                            if isinstance(mval, str) and len(mval) > 4 and mval.strip().lower() != node_value:
                                text_parts.append(mval)
                            elif isinstance(mval, list):
                                text_parts.extend(
                                    s for s in mval
                                    if isinstance(s, str) and len(s) > 4 and s.strip().lower() != node_value
                                )
                        text = " ".join(text_parts).strip()
                        if len(text) < 20:
                            continue
                        try:
                            extracted = extractor.extract_entities.remote(text)
                        except Exception:
                            continue
                        source_node_id = v.get("id", k[len(NODE_PREFIX):])
                        node_depth = v.get("depth", 0) + 1
                        new_edges = []
                        for etype_, vals in [
                            (EntityType.EMAIL.value, extracted.get("emails", [])),
                            (EntityType.USERNAME.value, extracted.get("usernames", [])),
                            (EntityType.DOMAIN.value, extracted.get("domains", [])),
                        ]:
                            for val in vals:
                                val = (val or "").strip()
                                if not val:
                                    continue
                                ek = _entity_key(etype_, val)
                                if ek == source_node_id:
                                    continue
                                nk = f"{NODE_PREFIX}{ek}"
                                if nk not in snapshot_stop:
                                    new_node = {
                                        "id": ek,
                                        "type": etype_,
                                        "value": val,
                                        "metadata": {"source": "gpu_extractor"},
                                        "depth": node_depth,
                                    }
                                    snapshot_stop[nk] = new_node
                                    write_stream_event(scan_id, "node", new_node)
                                new_edges.append({
                                    "source": source_node_id,
                                    "target": ek,
                                    "relationship": "extracted_by_gpu",
                                    "confidence": 0.8,
                                })
                        if new_edges:
                            snapshot_stop[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = new_edges
                            for edge in new_edges:
                                write_stream_event(scan_id, "edge", edge)
                except Exception:
                    pass
                graph_payload_stop = build_from_dict(snapshot_stop)
                scan_results[scan_id] = {
                    "status": ScanStatus.CANCELLED.value,
                    "graph": graph_payload_stop,
                    "error": None,
                    "entities_seen": seen_count,
                    "depth_reached": max_depth_reached,
                }
                write_stream_event(scan_id, "status", {
                    "status": ScanStatus.CANCELLED.value,
                    "entities_seen": seen_count,
                    "depth_reached": max_depth_reached,
                })
                break

        for ref in spawn_refs:
            try:
                ref.get(timeout=120)
            except Exception:
                pass

        snapshot: dict[str, Any] = {}
        for k in list(d.keys()):
            try:
                snapshot[k] = d[k]
            except Exception:
                pass

        # GPU post-processing: extract entities from node metadata text
        try:
            from inference.extractor import EntityExtractor
            extractor = EntityExtractor()
            for k, v in list(snapshot.items()):
                if not k.startswith(NODE_PREFIX) or not isinstance(v, dict):
                    continue
                meta = v.get("metadata", {}) or {}
                # Collect string values from metadata (exclude the node's own value to avoid self-extraction)
                node_value = v.get("value", "").strip().lower()
                text_parts: list[str] = []
                for mval in meta.values():
                    if isinstance(mval, str) and len(mval) > 4 and mval.strip().lower() != node_value:
                        text_parts.append(mval)
                    elif isinstance(mval, list):
                        text_parts.extend(
                            s for s in mval
                            if isinstance(s, str) and len(s) > 4 and s.strip().lower() != node_value
                        )
                text = " ".join(text_parts).strip()
                if len(text) < 20:
                    continue
                try:
                    extracted = extractor.extract_entities.remote(text)
                except Exception:
                    continue
                source_node_id = v.get("id", k[len(NODE_PREFIX):])
                node_depth = v.get("depth", 0) + 1
                new_edges: list[dict[str, Any]] = []
                for etype, vals in [
                    (EntityType.EMAIL.value, extracted.get("emails", [])),
                    (EntityType.USERNAME.value, extracted.get("usernames", [])),
                    (EntityType.DOMAIN.value, extracted.get("domains", [])),
                ]:
                    for val in vals:
                        val = (val or "").strip()
                        if not val:
                            continue
                        ek = _entity_key(etype, val)
                        if ek == source_node_id:
                            continue  # skip self-referential edges
                        nk = f"{NODE_PREFIX}{ek}"
                        if nk not in snapshot:
                            new_node: dict[str, Any] = {
                                "id": ek,
                                "type": etype,
                                "value": val,
                                "metadata": {"source": "gpu_extractor"},
                                "depth": node_depth,
                            }
                            snapshot[nk] = new_node
                            write_stream_event(scan_id, "node", new_node)
                        new_edges.append({
                            "source": source_node_id,
                            "target": ek,
                            "relationship": "extracted_by_gpu",
                            "confidence": 0.8,
                        })
                if new_edges:
                    snapshot[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = new_edges
                    for edge in new_edges:
                        write_stream_event(scan_id, "edge", edge)
        except Exception:
            pass  # GPU extraction is best-effort; don't fail the scan

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
        })

    except Exception as e:
        err = f"{e}\n{traceback.format_exc()}"
        scan_results[scan_id] = {
            "status": ScanStatus.FAILED.value,
            "graph": None,
            "error": err,
            "entities_seen": 0,
            "depth_reached": 0,
        }
        write_stream_event(scan_id, "status", {"status": ScanStatus.FAILED.value, "error": err})
