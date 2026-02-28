"""NetworkX graph construction from Dict, node/edge schema, serialization to JSON."""

from __future__ import annotations

import json
from typing import Any

import networkx as nx

# Dict key prefixes used by resolvers and orchestrator
NODE_PREFIX = "node_"
EDGES_BATCH_PREFIX = "edges_batch_"
SEEN_PREFIX = "seen_"


def build_from_dict(d: dict[str, Any]) -> dict[str, Any]:
    """
    Build graph payload from ephemeral Dict contents.
    Dict keys: node_<entity_key> -> node dict, edges_batch_<uuid> -> list of edge dicts.
    Returns JSON-serializable { "nodes": [...], "edges": [...] }.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_node_ids: set[str] = set()

    for key, val in d.items():
        if key.startswith(NODE_PREFIX) and isinstance(val, dict):
            node_id = key[len(NODE_PREFIX) :]
            if node_id not in seen_node_ids:
                seen_node_ids.add(node_id)
                nodes.append(_normalize_node(node_id, val))
        elif key.startswith(EDGES_BATCH_PREFIX) and isinstance(val, list):
            for e in val:
                if isinstance(e, dict) and "source" in e and "target" in e:
                    edges.append(_normalize_edge(e))

    return {"nodes": nodes, "edges": edges}


def _normalize_node(node_id: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Ensure node has id, type, value, metadata, depth."""
    return {
        "id": raw.get("id", node_id),
        "type": raw.get("type", "username"),
        "value": raw.get("value", ""),
        "metadata": raw.get("metadata", {}),
        "depth": raw.get("depth", 0),
    }


def _normalize_edge(raw: dict[str, Any]) -> dict[str, Any]:
    """Ensure edge has source, target, relationship, confidence."""
    return {
        "source": raw["source"],
        "target": raw["target"],
        "relationship": raw.get("relationship", "linked_to"),
        "confidence": raw.get("confidence", 1.0),
    }


def to_networkx(nodes: list[dict], edges: list[dict]) -> nx.DiGraph:
    """Build a NetworkX DiGraph from nodes/edges lists (for optional analysis)."""
    G = nx.DiGraph()
    for n in nodes:
        G.add_node(
            n["id"],
            type=n.get("type"),
            value=n.get("value"),
            metadata=n.get("metadata", {}),
            depth=n.get("depth", 0),
        )
    for e in edges:
        G.add_edge(
            e["source"],
            e["target"],
            relationship=e.get("relationship", "linked_to"),
            confidence=e.get("confidence", 1.0),
        )
    return G


def serialize_graph(graph_payload: dict[str, Any]) -> str:
    """Serialize graph payload to JSON string."""
    return json.dumps(graph_payload, default=str)
