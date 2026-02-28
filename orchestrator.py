"""
Main scan loop: named Queue + Dict by scan_id, fan-out to resolvers, build graph.
"""

import time
from typing import Any

import modal

from app import app, image, osint_secret
from graph import NODE_PREFIX, SEEN_PREFIX, build_from_dict
from models import Entity, EntityType, ScanConfig, ScanStatus
from stream import write_stream_event


def _entity_key(etype: str, value: str) -> str:
    v = (value or "").strip().lower()
    return f"{etype}:{v}"


@app.function(image=image, secrets=[osint_secret], timeout=1200)
def run_scan(scan_id: str, seed_entity: dict[str, Any], config_dict: dict[str, Any]) -> None:
    """
    Fan-out scan: named Queue + Dict keyed by scan_id, resolvers look them up by name.
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

    scan_results = modal.Dict.from_name("osint-scan-results", create_if_missing=True)
    q = modal.Queue.from_name(f"osint-q-{scan_id}", create_if_missing=True)
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)

    write_stream_event(scan_id, "status", {"status": ScanStatus.RUNNING.value, "entities_seen": 0})

    try:
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
        max_consecutive_empty = 4  # wait up to 4 * 15s = 60s of quiet before declaring done

        while True:
            if time.monotonic() - start >= timeout_seconds:
                d["stop"] = True
                break

            # Use a shorter poll interval so we're responsive; retry on empty
            try:
                items = q.get_many(50, timeout=15)
            except Exception:
                items = []

            if not items:
                # If we've spawned nothing and queue is empty, we're done
                if not spawn_refs:
                    break
                consecutive_empty += 1
                if consecutive_empty >= max_consecutive_empty:
                    break
                continue

            consecutive_empty = 0  # reset on any activity

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

                # Write intermediate status so /status reflects real progress
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

        # Wait for all spawned resolvers
        for ref in spawn_refs:
            try:
                ref.get(timeout=120)
            except Exception:
                pass

        # Snapshot graph from Dict
        snapshot: dict[str, Any] = {}
        for k in list(d.keys()):
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
        })

    except Exception as e:
        import traceback
        err = f"{e}\n{traceback.format_exc()}"
        scan_results[scan_id] = {
            "status": ScanStatus.FAILED.value,
            "graph": None,
            "error": err,
            "entities_seen": seen_count,
            "depth_reached": max_depth_reached,
        }
        write_stream_event(scan_id, "status", {"status": ScanStatus.FAILED.value, "error": err})
