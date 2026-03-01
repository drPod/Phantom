"""
Planner–Analyst orchestrator.

Two focused Claude contexts per scan turn:
  Planner — receives compressed analyst briefs, emits tool_use blocks
  Analyst — receives raw resolver output, writes the next brief

Each scan step: Planner picks resolvers → spawn Modal functions →
snapshot Dict → Analyst summarises raw diff → brief fed back to Planner.
"""

import importlib
import re
import time
import traceback
import uuid
from typing import Any

import modal
import modal.exception
from anthropic import Anthropic

from agent.analyst import call_analyst
from agent.planner import call_planner, format_system_prompt
from agent.report import generate_report
from agent.state import GraphState
from agent.tools import ALL_TOOLS, TOOL_NAME_TO_RESOLVER
from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX, build_from_dict
from models import Entity, EntityType, ScanConfig, ScanStatus
from resolvers.identity_correlator import correlate_identities
from scan_log import log_scan_event
from stream import write_stream_event

# ---------------------------------------------------------------------------
# Validation helpers (shared with GPU post-processing)
# ---------------------------------------------------------------------------

_IPV4_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_REGEX = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$"
)
_USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")


def _entity_key(etype: str, value: str) -> str:
    v = (value or "").strip().lower()
    return f"{etype}:{v}"


def _is_ip_address(s: str) -> bool:
    if not s or not s.strip():
        return False
    m = _IPV4_PATTERN.match(s.strip())
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def _is_valid_extracted_entity(etype: str, val: str) -> bool:
    val = (val or "").strip()
    if not val:
        return False
    if etype == EntityType.EMAIL.value:
        if not _EMAIL_REGEX.match(val):
            return False
        if _is_ip_address(val):
            return False
        domain_part = val.split("@")[-1]
        if _is_ip_address(domain_part):
            return False
        return True
    if etype == EntityType.DOMAIN.value:
        val_lower = val.lower()
        if len(val_lower) <= 3:
            return False
        if _is_ip_address(val_lower):
            return False
        return bool(_DOMAIN_REGEX.match(val_lower))
    if etype == EntityType.USERNAME.value:
        return bool(_USERNAME_REGEX.match(val))
    return True


# ---------------------------------------------------------------------------
# Safe Modal helpers
# ---------------------------------------------------------------------------

def _narrate(scan_id: str, message: str, category: str = "info") -> None:
    """Emit a human-readable narration event over the SSE stream."""
    write_stream_event(scan_id, "narration", {"message": message, "category": category})


def _safe_dict_put(d: Any, key: str, value: Any, scan_id: str) -> None:
    try:
        d[key] = value
    except Exception as e:
        log_scan_event(
            scan_id, "dict_put_failed",
            error=str(e), key=key, data_preview=str(value)[:500],
        )
        raise


def _safe_scan_results_put(scan_results: Any, scan_id: str, payload: dict) -> None:
    try:
        scan_results[scan_id] = payload
    except Exception as e:
        log_scan_event(
            scan_id, "scan_results_put_failed",
            error=str(e), data_preview=str(payload)[:500],
        )
        raise


def _snapshot_dict(d: Any, scan_id: str) -> dict[str, Any]:
    snapshot: dict[str, Any] = {}
    for k in list(d.keys()):
        try:
            snapshot[k] = d[k]
        except Exception as e:
            log_scan_event(scan_id, "dict_get_failed", error=str(e), key=k)
    return snapshot


# ---------------------------------------------------------------------------
# Resolver dispatch
# ---------------------------------------------------------------------------

_FN_CACHE: dict[str, Any] = {}


def _get_resolver_fn(tool_name: str) -> Any:
    """Dynamically import the Modal function handle for *tool_name*."""
    if tool_name in _FN_CACHE:
        return _FN_CACHE[tool_name]
    dotted = TOOL_NAME_TO_RESOLVER[tool_name]
    module_path, func_name = dotted.rsplit(".", 1)
    mod = importlib.import_module(module_path)
    fn = getattr(mod, func_name)
    _FN_CACHE[tool_name] = fn
    return fn


# ---------------------------------------------------------------------------
# GPU post-processing
# ---------------------------------------------------------------------------

_GPU_POSTPROCESS_BUDGET = 90  # max wall-clock seconds for the entire GPU enrichment phase

def _gpu_postprocess(snapshot: dict[str, Any], scan_id: str) -> dict[str, Any]:
    """Run GPU entity extraction over node metadata; mutates & returns *snapshot*."""
    gpu_start = time.monotonic()
    try:
        from inference.extractor import EntityExtractor
        extractor = EntityExtractor()

        # Absorb GPU cold-start cost with a single warm-up call.
        # If the container can't start within 120s, skip GPU enrichment entirely.
        try:
            warmup_call = extractor.extract_entities.spawn("warmup")
            warmup_call.get(timeout=120)
        except (TimeoutError, modal.exception.FunctionTimeoutError):
            log_scan_event(scan_id, "gpu_warmup_timeout")
            return snapshot

        for k, v in list(snapshot.items()):
            if time.monotonic() - gpu_start > _GPU_POSTPROCESS_BUDGET:
                log_scan_event(scan_id, "gpu_extraction_budget_exhausted",
                               elapsed=time.monotonic() - gpu_start)
                break
            if not k.startswith(NODE_PREFIX) or not isinstance(v, dict):
                continue
            meta = v.get("metadata", {}) or {}
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
            source_node_id = v.get("id", k[len(NODE_PREFIX):])
            node_depth = v.get("depth", 0) + 1
            try:
                log_scan_event(scan_id, "gpu_extraction_started", node_id=source_node_id)
                call = extractor.extract_entities.spawn(text)
                extracted = call.get(timeout=60)
            except (TimeoutError, modal.exception.FunctionTimeoutError) as ex:
                log_scan_event(scan_id, "gpu_extraction_timeout", node_id=source_node_id, error=str(ex))
                continue
            except Exception as ex:
                log_scan_event(scan_id, "gpu_extraction_failed", node_id=source_node_id, error=str(ex))
                continue
            new_edges: list[dict[str, Any]] = []
            nodes_added = 0
            for etype, vals in [
                (EntityType.EMAIL.value, extracted.get("emails", [])),
                (EntityType.USERNAME.value, extracted.get("usernames", [])),
                (EntityType.DOMAIN.value, extracted.get("domains", [])),
            ]:
                for val in vals:
                    val = (val or "").strip()
                    if not val or not _is_valid_extracted_entity(etype, val):
                        continue
                    ek = _entity_key(etype, val)
                    if ek == source_node_id:
                        continue
                    nk = f"{NODE_PREFIX}{ek}"
                    if nk not in snapshot:
                        nodes_added += 1
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
            log_scan_event(
                scan_id, "gpu_extraction_completed",
                node_id=source_node_id, nodes_found=nodes_added, edges_found=len(new_edges),
            )
            if new_edges:
                snapshot[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = new_edges
                for edge in new_edges:
                    write_stream_event(scan_id, "edge", edge)
    except Exception as gpu_ex:
        log_scan_event(scan_id, "gpu_extraction_error", error=str(gpu_ex))
    return snapshot


# ---------------------------------------------------------------------------
# Breach identity correlation
# ---------------------------------------------------------------------------

def _index_pivot(
    indexes: dict[str, dict[str, set[str]]],
    pivot_type: str,
    pivot_val: Any,
    node_id: str,
) -> None:
    """Add *node_id* to the inverted index for *pivot_val* under *pivot_type*."""
    if not pivot_val or not isinstance(pivot_val, str):
        return
    v = pivot_val.strip().lower()
    if not v or len(v) < 4:
        return
    indexes[pivot_type].setdefault(v, set()).add(node_id)


def _breach_correlate(snapshot: dict[str, Any], scan_id: str) -> dict[str, Any]:
    """Find identities linked by shared breach pivots (password hash, IP, phone).

    Scans all breach metadata in the snapshot and emits undirected correlation
    edges between any two identity nodes that share a password hash, IP address,
    or phone number across their breach entries.  Runs as a post-processing step
    so it never touches the Planner/Analyst context.
    """
    indexes: dict[str, dict[str, set[str]]] = {
        "password_hash": {},
        "ip_address": {},
        "phone": {},
    }

    for k, v in snapshot.items():
        if not k.startswith(NODE_PREFIX) or not isinstance(v, dict):
            continue
        node_id = v.get("id", k[len(NODE_PREFIX):])
        meta = v.get("metadata") or {}

        for entry in (meta.get("dehashed_entries") or []):
            if not isinstance(entry, dict):
                continue
            _index_pivot(indexes, "password_hash", entry.get("hashed_password"), node_id)
            _index_pivot(indexes, "ip_address", entry.get("ip_address"), node_id)
            _index_pivot(indexes, "phone", entry.get("phone"), node_id)

        for entry in (meta.get("leakcheck_entries") or []):
            if not isinstance(entry, dict):
                continue
            _index_pivot(indexes, "password_hash", entry.get("hashed_password"), node_id)

    confidence_map = {
        "password_hash": 0.85,
        "ip_address": 0.6,
        "phone": 0.9,
    }
    new_edges: list[dict[str, Any]] = []

    for pivot_type, pivot_index in indexes.items():
        for pivot_val, node_ids in pivot_index.items():
            if len(node_ids) < 2:
                continue
            sorted_ids = sorted(node_ids)
            for i, src in enumerate(sorted_ids):
                for tgt in sorted_ids[i + 1:]:
                    new_edges.append({
                        "source": src,
                        "target": tgt,
                        "relationship": f"shared_{pivot_type}",
                        "confidence": confidence_map[pivot_type],
                    })

    if new_edges:
        snapshot[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = new_edges
        for edge in new_edges:
            write_stream_event(scan_id, "edge", edge)
        log_scan_event(
            scan_id, "breach_correlation_completed",
            edges_added=len(new_edges),
        )

    return snapshot


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

_MAX_AGENT_TURNS = 30
_RESOLVER_TIMEOUT = 120


@app.function(image=image, secrets=[osint_secret], timeout=1200)
def run_scan(scan_id: str, seed_entity: dict[str, Any], config_dict: dict[str, Any]) -> None:
    """Planner–Analyst scan loop.

    Planner (multi-turn, lean context)  picks resolver tools.
    Analyst (single-turn, raw data)     writes the compressed brief.
    """

    scan_results = modal.Dict.from_name("osint-scan-results", create_if_missing=True)
    log_scan_event(scan_id, "scan_started", seed_entity=seed_entity, config=config_dict)

    d = None

    try:
        config = ScanConfig.model_validate(config_dict)
        seed = Entity.model_validate({
            **seed_entity,
            "source": seed_entity.get("source", "user"),
            "depth": seed_entity.get("depth", 0),
        })
        timeout_seconds = config.timeout_minutes * 60
        start = time.monotonic()

        d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)

        seed_node: dict[str, Any] = {
            "id": "seed",
            "type": seed.type.value,
            "value": seed.value,
            "metadata": {"seed": True},
            "depth": 0,
        }
        _safe_dict_put(d, f"{NODE_PREFIX}seed", seed_node, scan_id)
        write_stream_event(scan_id, "node", seed_node)
        _narrate(scan_id, f"Starting investigation of {seed.type.value}: {seed.value}", "start")

        _safe_scan_results_put(scan_results, scan_id, {
            "status": ScanStatus.RUNNING.value,
            "graph": None,
            "error": None,
            "entities_seen": 1,
            "depth_reached": 0,
        })
        write_stream_event(scan_id, "status", {"status": ScanStatus.RUNNING.value, "entities_seen": 1})

        # -- initialise shared state --
        client = Anthropic()
        graph_state = GraphState(scan_id)

        initial_snapshot = _snapshot_dict(d, scan_id)
        graph_state.sync_from_dict(initial_snapshot)

        planner_system = format_system_prompt(
            max_depth=config.max_depth,
            max_entities=config.max_entities,
            scan_id=scan_id,
        )

        messages: list[dict[str, Any]] = [{
            "role": "user",
            "content": (
                f"Investigate {seed.type.value}: {seed.value}\n\n"
                f"Current graph state:\n{graph_state.full_summary()}"
            ),
        }]

        known_entities: set[str] = {"seed"}
        entities_seen = 1  # seed counts
        max_depth_reached = 0
        final_status = ScanStatus.COMPLETED
        cancelled = False

        for _turn in range(_MAX_AGENT_TURNS):
            # -- guard rails --
            if time.monotonic() - start >= timeout_seconds:
                log_scan_event(scan_id, "scan_timeout", timeout_seconds=timeout_seconds)
                break
            if entities_seen >= config.max_entities:
                break
            if "stop" in d:
                cancelled = True
                break

            # ========== STEP 1: Planner picks tools ==========
            response = call_planner(client, planner_system, messages, ALL_TOOLS)
            log_scan_event(scan_id, "planner_turn", turn=_turn)

            if response.stop_reason != "tool_use":
                break

            tool_blocks = [b for b in response.content if b.type == "tool_use"]
            finish_blocks = [b for b in tool_blocks if b.name == "finish_investigation"]
            if finish_blocks:
                reason = finish_blocks[0].input.get("reason", "")
                log_scan_event(scan_id, "agent_finished", reason=reason)
                messages.append({"role": "assistant", "content": response.content})
                messages.append({
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": b.id, "content": "Acknowledged."}
                        for b in finish_blocks
                    ],
                })
                break

            resolver_blocks = [b for b in tool_blocks if b.name in TOOL_NAME_TO_RESOLVER]
            if resolver_blocks:
                resolver_names = ", ".join(b.name.replace("_", " ") for b in resolver_blocks[:3])
                suffix = f" (+{len(resolver_blocks) - 3} more)" if len(resolver_blocks) > 3 else ""
                _narrate(scan_id, f"Turn {_turn + 1}: dispatching {len(resolver_blocks)} resolver(s) — {resolver_names}{suffix}", "resolver")

            # ========== STEP 2: Spawn resolvers in parallel ==========
            spawn_refs: list[tuple[Any, str, str, float]] = []
            skipped_results: dict[str, str] = {}

            for block in resolver_blocks:
                inp = block.input

                # correlate_identities is a graph-wide operation — it has no
                # entity_value/type/depth and must bypass per-entity guard rails.
                if block.name == "correlate_identities":
                    ek = "correlate_identities:graph"
                    if graph_state.is_resolved(block.name, ek):
                        skipped_results[block.id] = "Identity correlation already ran this turn."
                        continue
                    graph_state.mark_resolved(block.name, ek)
                    fn = _get_resolver_fn(block.name)
                    t0 = time.monotonic()
                    ref = fn.spawn("", "", 0, "graph", scan_id)
                    log_scan_event(scan_id, "resolver_spawned", resolver=block.name, entity_key=ek, depth=0)
                    spawn_refs.append((ref, block.name, ek, t0))
                    continue

                raw_val = inp.get("entity_value") or ""
                if isinstance(raw_val, dict):
                    raw_val = raw_val.get("value", "") or str(raw_val)
                entity_val = str(raw_val).strip()
                entity_type = inp.get("entity_type", "")
                depth = inp.get("depth", 0)
                source_key = inp.get("source_entity_key", "seed")
                ek = _entity_key(entity_type, entity_val)

                if graph_state.is_resolved(block.name, ek):
                    skipped_results[block.id] = f"Already ran {block.name} on {ek}."
                    log_scan_event(scan_id, "entity_skipped", reason="dedup", entity_key=ek, resolver=block.name)
                    continue
                if depth > config.max_depth:
                    skipped_results[block.id] = f"Depth {depth} exceeds max_depth {config.max_depth}."
                    log_scan_event(scan_id, "entity_skipped", reason="depth_limit", entity_key=ek)
                    continue
                if ek not in known_entities and entities_seen >= config.max_entities:
                    skipped_results[block.id] = f"Entity limit ({config.max_entities}) reached."
                    log_scan_event(scan_id, "entity_skipped", reason="max_entities", entity_key=ek)
                    continue

                graph_state.mark_resolved(block.name, ek)
                if ek not in known_entities:
                    known_entities.add(ek)
                    entities_seen += 1
                if depth > max_depth_reached:
                    max_depth_reached = depth

                fn = _get_resolver_fn(block.name)
                t0 = time.monotonic()
                ref = fn.spawn(entity_val, entity_type, depth, source_key, scan_id)
                log_scan_event(
                    scan_id, "resolver_spawned",
                    resolver=block.name, entity_key=ek, depth=depth,
                )
                spawn_refs.append((ref, block.name, ek, t0))

            # -- wait for all spawned resolvers --
            for ref, resolver_name, ek, t0 in spawn_refs:
                try:
                    ref.get(timeout=_RESOLVER_TIMEOUT)
                    duration = time.monotonic() - t0
                    log_scan_event(
                        scan_id, "resolver_completed",
                        resolver=resolver_name, entity_key=ek,
                        duration=duration,
                    )
                    _narrate(
                        scan_id,
                        f"{resolver_name.replace('_', ' ')} completed for {ek} ({duration:.1f}s)",
                        "result",
                    )
                except Exception as e:
                    is_timeout = isinstance(e, TimeoutError) or "timeout" in str(e).lower()
                    log_scan_event(
                        scan_id, "resolver_failed",
                        resolver=resolver_name, entity_key=ek,
                        error=str(e), timeout=is_timeout,
                    )
                    reason = "timed out" if is_timeout else "failed"
                    _narrate(
                        scan_id,
                        f"{resolver_name.replace('_', ' ')} {reason} for {ek}",
                        "warning",
                    )

            # ========== STEP 3: Sync graph state ==========
            snapshot = _snapshot_dict(d, scan_id)
            diff = graph_state.sync_from_dict(snapshot)

            graph_payload = build_from_dict(snapshot)

            _safe_scan_results_put(scan_results, scan_id, {
                "status": ScanStatus.RUNNING.value,
                "graph": graph_payload,
                "error": None,
                "entities_seen": entities_seen,
                "depth_reached": max_depth_reached,
            })
            write_stream_event(scan_id, "status", {
                "status": ScanStatus.RUNNING.value,
                "entities_seen": entities_seen,
                "depth_reached": max_depth_reached,
            })

            # ========== STEP 4: Analyst produces brief from raw data ==========
            brief = call_analyst(
                client,
                raw_nodes=diff.new_nodes,
                raw_edges=diff.new_edges,
                graph_summary=graph_state.full_summary(),
            )
            log_scan_event(scan_id, "analyst_turn", turn=_turn,
                           brief_len=len(brief), new_nodes=len(diff.new_nodes))
            if diff.new_nodes:
                _narrate(
                    scan_id,
                    f"Analyst reviewed {len(diff.new_nodes)} new node(s), {len(diff.new_edges)} edge(s) — identifying leads",
                    "analysis",
                )

            # ========== STEP 5: Feed brief back to planner as tool_results ==========
            messages.append({"role": "assistant", "content": response.content})

            brief_with_stats = (
                f"Analyst brief:\n{brief}\n\n"
                f"entities_seen={entities_seen}/{config.max_entities}"
            )

            tool_results: list[dict[str, Any]] = []
            first_resolver = True
            for block in tool_blocks:
                if block.name == "finish_investigation":
                    continue
                if block.id in skipped_results:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": skipped_results[block.id],
                    })
                elif block.name in TOOL_NAME_TO_RESOLVER:
                    if first_resolver:
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": brief_with_stats,
                        })
                        first_resolver = False
                    else:
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": "Completed (analyst brief included in first tool result).",
                        })

            messages.append({"role": "user", "content": tool_results})

        # -- finalize: build graph first, THEN try GPU enrichment --
        snapshot = _snapshot_dict(d, scan_id)
        graph_payload = build_from_dict(snapshot)
        status = ScanStatus.CANCELLED if cancelled else final_status

        _safe_scan_results_put(scan_results, scan_id, {
            "status": status.value,
            "graph": graph_payload,
            "error": None,
            "entities_seen": entities_seen,
            "depth_reached": max_depth_reached,
        })

        _narrate(scan_id, "Running AI entity extraction on collected metadata...", "enrichment")
        snapshot = _gpu_postprocess(snapshot, scan_id)
        _narrate(scan_id, "Correlating breach identities across nodes...", "enrichment")
        snapshot = _breach_correlate(snapshot, scan_id)
        _narrate(scan_id, "Running cross-platform identity correlation...", "enrichment")
        snapshot = correlate_identities(snapshot, scan_id)
        graph_payload = build_from_dict(snapshot)

        # -- generate final intelligence report over the completed graph --
        report: str | None = None
        try:
            log_scan_event(scan_id, "report_generation_started")
            _narrate(scan_id, "Generating intelligence report...", "report")
            report = generate_report(
                client,
                graph_payload=graph_payload,
                seed_entity=seed_entity,
                scan_config=config_dict,
                entities_seen=entities_seen,
                depth_reached=max_depth_reached,
            )
            log_scan_event(scan_id, "report_generation_completed", report_len=len(report))
            write_stream_event(scan_id, "report", {"report": report})
        except Exception as report_err:
            log_scan_event(scan_id, "report_generation_failed", error=str(report_err))

        node_count = len(graph_payload.get("nodes", [])) if graph_payload else entities_seen
        _narrate(
            scan_id,
            f"Investigation complete — {node_count} nodes discovered across {max_depth_reached} depth level(s)",
            "complete",
        )
        log_scan_event(
            scan_id, "scan_finalized",
            status=status.value,
            entities_seen=entities_seen,
            depth_reached=max_depth_reached,
        )
        _safe_scan_results_put(scan_results, scan_id, {
            "status": status.value,
            "graph": graph_payload,
            "report": report,
            "error": None,
            "entities_seen": entities_seen,
            "depth_reached": max_depth_reached,
        })
        write_stream_event(scan_id, "status", {
            "status": status.value,
            "entities_seen": entities_seen,
            "depth_reached": max_depth_reached,
        })

    except Exception as e:
        err = f"{e}\n{traceback.format_exc()}"
        partial_graph = None
        try:
            if d is not None:
                partial_snapshot = _snapshot_dict(d, scan_id)
                partial_graph = build_from_dict(partial_snapshot)
        except Exception:
            pass
        log_scan_event(
            scan_id, "scan_finalized",
            status=ScanStatus.FAILED.value,
            entities_seen=0, depth_reached=0,
        )
        try:
            scan_results[scan_id] = {
                "status": ScanStatus.FAILED.value,
                "graph": partial_graph,
                "error": err,
                "entities_seen": 0,
                "depth_reached": 0,
            }
        except Exception as put_err:
            log_scan_event(
                scan_id, "scan_results_put_failed",
                error=str(put_err), data_preview=str(err)[:500],
            )
            raise
        write_stream_event(scan_id, "status", {"status": ScanStatus.FAILED.value, "error": err})
