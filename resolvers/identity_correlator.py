"""Identity correlator: GPU-backed cross-platform identity matching.

Runs as a post-processing step after all resolvers finish.  For every pair of
same-type nodes that share at least one meaningful token (name, bio, handle),
it calls EntityExtractor.score_identity_match() on the GPU and emits a
``likely_same_person`` edge when the score meets the confidence threshold.

Also exposed as a Modal @app.function so the Planner agent can trigger it
mid-scan via the ``correlate_identities`` tool.
"""

from __future__ import annotations

import itertools
import logging
import re
import time
import uuid
from typing import Any

import modal
import modal.exception

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from scan_log import log_scan_event
from stream import write_stream_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

_MATCH_THRESHOLD = 0.75       # minimum score_identity_match score to emit an edge
_GPU_BUDGET_SECONDS = 90      # wall-clock cap for the entire correlation phase
_PER_CALL_TIMEOUT = 30        # seconds per individual GPU call
_MAX_GPU_CALLS = 50           # hard cap on pairwise comparisons
_MIN_TOKEN_OVERLAP = 1        # minimum shared meaningful tokens to survive pre-filter
_MIN_TOKEN_LENGTH = 3         # tokens shorter than this are ignored

# Entity types worth comparing (platform_profile nodes carry the richest data)
_COMPARABLE_TYPES = {"username", "email", "platform_profile"}

# Metadata fields that carry identity-bearing text, in priority order
_PROFILE_TEXT_FIELDS = [
    "name", "display_name", "bio", "bio_snippet",
    "reddit_bio", "hn_about",
    "login", "gravatar_username",
    "location", "reddit_inferred_location",
    "company",
]


# ---------------------------------------------------------------------------
# Profile extraction helpers
# ---------------------------------------------------------------------------

def _extract_profile_dict(node: dict[str, Any]) -> dict[str, Any]:
    """Return a compact, comparable dict from a node for GPU scoring."""
    meta = node.get("metadata") or {}
    profile: dict[str, Any] = {
        "id": node.get("id", ""),
        "type": node.get("type", ""),
        "value": node.get("value", ""),
    }
    for field in _PROFILE_TEXT_FIELDS:
        val = meta.get(field)
        if val and isinstance(val, str) and val.strip():
            profile[field] = val.strip()[:200]
    # Include confirmed platform hits as a list of site names
    confirmed = meta.get("confirmed_profiles") or []
    if confirmed:
        profile["platforms"] = [
            p.get("site_name", "") for p in confirmed[:10] if isinstance(p, dict)
        ]
    return profile


def _tokenize(text: str) -> set[str]:
    """Lower-case word tokens, filtering short/common ones."""
    return {
        t for t in re.findall(r"[a-z0-9_-]+", text.lower())
        if len(t) >= _MIN_TOKEN_LENGTH
    }


def _profile_tokens(profile: dict[str, Any]) -> set[str]:
    """Collect all meaningful tokens from a profile dict."""
    tokens: set[str] = set()
    for v in profile.values():
        if isinstance(v, str):
            tokens |= _tokenize(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    tokens |= _tokenize(item)
    return tokens


# ---------------------------------------------------------------------------
# Candidate pair builder
# ---------------------------------------------------------------------------

def _build_candidate_pairs(
    nodes: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]]:
    """Return (node_a, node_b, profile_a, profile_b) pairs that survive pre-filtering.

    Pre-filter rules (applied cheaply, before any GPU call):
    1. Both nodes must be of a comparable type.
    2. Nodes must be of the same type (comparing username vs email is rarely useful).
    3. Their profile token sets must share at least _MIN_TOKEN_OVERLAP tokens.
    4. Their node IDs must differ.
    """
    # Group by type
    by_type: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        ntype = node.get("type", "")
        if ntype in _COMPARABLE_TYPES:
            by_type.setdefault(ntype, []).append(node)

    candidates: list[tuple[dict, dict, dict, dict]] = []
    for ntype, type_nodes in by_type.items():
        if len(type_nodes) < 2:
            continue
        profiles = [_extract_profile_dict(n) for n in type_nodes]
        token_sets = [_profile_tokens(p) for p in profiles]

        for (i, node_a), (j, node_b) in itertools.combinations(enumerate(type_nodes), 2):
            if node_a.get("id") == node_b.get("id"):
                continue
            shared = token_sets[i] & token_sets[j]
            if len(shared) >= _MIN_TOKEN_OVERLAP:
                candidates.append((node_a, node_b, profiles[i], profiles[j]))

    return candidates


# ---------------------------------------------------------------------------
# Core post-processing function (called directly from orchestrator)
# ---------------------------------------------------------------------------

def correlate_identities(snapshot: dict[str, Any], scan_id: str) -> dict[str, Any]:
    """Compare same-type nodes via GPU and emit likely_same_person edges.

    Mutates and returns *snapshot* (same contract as _gpu_postprocess and
    _breach_correlate in orchestrator.py).
    """
    phase_start = time.monotonic()

    nodes = [
        v for k, v in snapshot.items()
        if k.startswith(NODE_PREFIX) and isinstance(v, dict)
    ]

    if len(nodes) < 2:
        return snapshot

    candidates = _build_candidate_pairs(nodes)
    if not candidates:
        log_scan_event(scan_id, "identity_correlation_skipped", reason="no_candidate_pairs")
        return snapshot

    # Cap to budget
    candidates = candidates[:_MAX_GPU_CALLS]
    log_scan_event(
        scan_id, "identity_correlation_started",
        candidate_pairs=len(candidates), total_nodes=len(nodes),
    )

    try:
        from inference.extractor import EntityExtractor
        extractor = EntityExtractor()

        # Warm up the GPU container once before the batch
        try:
            warmup = extractor.score_identity_match.spawn({"warmup": True}, {"warmup": True})
            warmup.get(timeout=120)
        except (TimeoutError, modal.exception.FunctionTimeoutError):
            log_scan_event(scan_id, "identity_correlation_warmup_timeout")
            return snapshot

        new_edges: list[dict[str, Any]] = []
        calls_made = 0

        for node_a, node_b, profile_a, profile_b in candidates:
            if time.monotonic() - phase_start > _GPU_BUDGET_SECONDS:
                log_scan_event(
                    scan_id, "identity_correlation_budget_exhausted",
                    elapsed=time.monotonic() - phase_start,
                    calls_made=calls_made,
                )
                break

            id_a = node_a.get("id", "")
            id_b = node_b.get("id", "")

            try:
                call = extractor.score_identity_match.spawn(profile_a, profile_b)
                score: float = call.get(timeout=_PER_CALL_TIMEOUT)
                calls_made += 1
            except (TimeoutError, modal.exception.FunctionTimeoutError) as ex:
                log_scan_event(
                    scan_id, "identity_correlation_timeout",
                    node_a=id_a, node_b=id_b, error=str(ex),
                )
                continue
            except Exception as ex:
                log_scan_event(
                    scan_id, "identity_correlation_call_failed",
                    node_a=id_a, node_b=id_b, error=str(ex),
                )
                continue

            if score >= _MATCH_THRESHOLD:
                edge: dict[str, Any] = {
                    "source": id_a,
                    "target": id_b,
                    "relationship": "likely_same_person",
                    "confidence": round(score, 3),
                }
                new_edges.append(edge)
                log_scan_event(
                    scan_id, "identity_correlation_match",
                    node_a=id_a, node_b=id_b, score=score,
                )

        if new_edges:
            batch_key = f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"
            snapshot[batch_key] = new_edges
            for edge in new_edges:
                write_stream_event(scan_id, "edge", edge)

        log_scan_event(
            scan_id, "identity_correlation_completed",
            calls_made=calls_made,
            matches_found=len(new_edges),
            elapsed=round(time.monotonic() - phase_start, 2),
        )

    except Exception as ex:
        log_scan_event(scan_id, "identity_correlation_error", error=str(ex))
        # Fallback: lightweight token-overlap heuristic when GPU is unavailable
        try:
            snapshot = _fallback_correlate(candidates, snapshot, scan_id)
        except Exception as fb_ex:
            log_scan_event(scan_id, "identity_correlation_fallback_error", error=str(fb_ex))

    return snapshot


def _fallback_correlate(
    candidates: list,
    snapshot: dict[str, Any],
    scan_id: str,
) -> dict[str, Any]:
    """String-similarity fallback when GPU inference is unavailable.

    Uses Jaccard token overlap as a proxy for identity match confidence.
    Emits likely_same_person edges with confidence capped at 0.74 (below
    the GPU threshold) so downstream consumers can distinguish fallback results.
    """
    new_edges: list[dict[str, Any]] = []
    for node_a, node_b, profile_a, profile_b in candidates[:_MAX_GPU_CALLS]:
        tokens_a = _profile_tokens(profile_a)
        tokens_b = _profile_tokens(profile_b)
        if not tokens_a or not tokens_b:
            continue
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        jaccard = len(intersection) / len(union) if union else 0.0
        # Require >=3 shared tokens and >=40% overlap for a fallback match
        if len(intersection) >= 3 and jaccard >= 0.40:
            score = round(min(jaccard * 0.9, 0.74), 3)  # cap below GPU threshold
            edge: dict[str, Any] = {
                "source": node_a.get("id", ""),
                "target": node_b.get("id", ""),
                "relationship": "likely_same_person",
                "confidence": score,
                "fallback": True,
            }
            new_edges.append(edge)
            log_scan_event(
                scan_id, "identity_correlation_fallback_match",
                node_a=node_a.get("id"), node_b=node_b.get("id"),
                jaccard=jaccard, shared_tokens=list(intersection)[:5],
            )
    if new_edges:
        batch_key = f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"
        snapshot[batch_key] = new_edges
        for edge in new_edges:
            write_stream_event(scan_id, "edge", edge)
    log_scan_event(
        scan_id, "identity_correlation_fallback_completed",
        matches_found=len(new_edges), candidates_checked=len(candidates),
    )
    return snapshot


# ---------------------------------------------------------------------------
# Modal @app.function — agent-callable variant
# ---------------------------------------------------------------------------

@app.function(image=image, secrets=[osint_secret], timeout=300)
@modal.concurrent(max_inputs=5)
def correlate_identities_tool(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    scan_id: str = "",
) -> None:
    """Agent-callable wrapper: loads the current scan Dict and runs correlation.

    The standard resolver signature is preserved so the orchestrator dispatch
    path works without special-casing.  entity_value / entity_type / depth /
    source_entity_key are accepted but unused — only scan_id matters.
    """
    if not scan_id:
        return

    try:
        _correlate_identities_tool_impl(scan_id)
    except Exception as exc:
        logger.error("correlate_identities_tool top-level failure (scan=%s): %s", scan_id, exc)
        try:
            log_scan_event(scan_id, "identity_correlator_failed", error=str(exc))
        except Exception:
            pass


def _correlate_identities_tool_impl(scan_id: str) -> None:
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)

    # Guard: ensure we have enough nodes before attempting correlation
    try:
        all_keys = list(d.keys())
    except Exception as exc:
        log_scan_event(scan_id, "identity_correlator_dict_read_failed", error=str(exc))
        return

    node_keys = [k for k in all_keys if k.startswith(NODE_PREFIX)]
    if len(node_keys) < 2:
        log_scan_event(scan_id, "identity_correlation_skipped",
                       reason="insufficient_nodes", node_count=len(node_keys))
        return

    # Snapshot the Dict into a plain dict
    snapshot: dict[str, Any] = {}
    for k in all_keys:
        try:
            snapshot[k] = d[k]
        except Exception:
            pass

    snapshot = correlate_identities(snapshot, scan_id)

    # Write any new edge batches back to the Dict so the orchestrator sees them
    existing_keys = set(all_keys)
    for k, v in snapshot.items():
        if k.startswith(EDGES_BATCH_PREFIX) and k not in existing_keys:
            try:
                d[k] = v
            except Exception as ex:
                log_scan_event(
                    scan_id, "identity_correlator_dict_put_failed",
                    key=k, error=str(ex),
                )
