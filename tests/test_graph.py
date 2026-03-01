"""Unit tests for graph module (nodes, edges, build_from_dict)."""

from graph import (
    EDGES_BATCH_PREFIX,
    NODE_PREFIX,
    build_from_dict,
    serialize_graph,
    to_networkx,
)


def test_build_from_dict_basic():
    """Basic node and edge extraction."""
    d = {
        f"{NODE_PREFIX}seed": {
            "id": "seed",
            "type": "username",
            "value": "test",
            "metadata": {"seed": True},
            "depth": 0,
        },
        f"{NODE_PREFIX}username:johndoe": {
            "id": "username:johndoe",
            "type": "username",
            "value": "johndoe",
            "metadata": {},
            "depth": 1,
        },
        f"{EDGES_BATCH_PREFIX}abc123": [
            {
                "source": "seed",
                "target": "username:johndoe",
                "relationship": "resolved",
                "confidence": 1.0,
            }
        ],
    }
    result = build_from_dict(d)
    assert len(result["nodes"]) == 2
    assert len(result["edges"]) == 1
    assert result["edges"][0]["source"] == "seed"
    assert result["edges"][0]["target"] == "username:johndoe"


def test_build_from_dict_filters_orphan_edges():
    """Edges pointing to non-existent nodes are filtered out."""
    d = {
        f"{NODE_PREFIX}seed": {"id": "seed", "type": "username", "value": "x", "metadata": {}, "depth": 0},
        f"{EDGES_BATCH_PREFIX}x": [
            {"source": "seed", "target": "username:real", "relationship": "r", "confidence": 1.0},
            {"source": "seed", "target": "email:ghost@x.com", "relationship": "r", "confidence": 1.0},
        ],
    }
    # Only seed exists; username:real and email:ghost@x.com do not
    result = build_from_dict(d)
    assert len(result["nodes"]) == 1
    assert len(result["edges"]) == 0  # both edges reference non-existent targets


def test_build_from_dict_dedup_by_node_id():
    """Deduplication uses node['id'], not dict key."""
    d = {
        f"{NODE_PREFIX}username:alice": {
            "id": "username:alice",
            "type": "username",
            "value": "alice",
            "metadata": {},
            "depth": 1,
        },
        f"{NODE_PREFIX}username:bob": {
            "id": "username:bob",
            "type": "username",
            "value": "bob",
            "metadata": {},
            "depth": 1,
        },
        f"{EDGES_BATCH_PREFIX}x": [
            {"source": "username:alice", "target": "username:bob", "relationship": "linked", "confidence": 1.0}
        ],
    }
    result = build_from_dict(d)
    assert len(result["nodes"]) == 2
    assert len(result["edges"]) == 1


def test_build_from_dict_explicit_id_overrides_key():
    """When payload has explicit id, it overrides key for dedup."""
    d = {
        f"{NODE_PREFIX}foo": {"id": "bar", "type": "username", "value": "bar", "metadata": {}, "depth": 1},
        f"{EDGES_BATCH_PREFIX}x": [{"source": "bar", "target": "bar", "relationship": "self", "confidence": 1.0}],
    }
    result = build_from_dict(d)
    assert len(result["nodes"]) == 1
    assert result["nodes"][0]["id"] == "bar"
    assert len(result["edges"]) == 1


def test_to_networkx():
    """NetworkX conversion works with normalized nodes/edges."""
    nodes = [
        {"id": "seed", "type": "username", "value": "x", "metadata": {}, "depth": 0},
        {"id": "username:a", "type": "username", "value": "a", "metadata": {}, "depth": 1},
    ]
    edges = [{"source": "seed", "target": "username:a", "relationship": "r", "confidence": 0.9}]
    G = to_networkx(nodes, edges)
    assert G.number_of_nodes() == 2
    assert G.number_of_edges() == 1
    assert G.has_edge("seed", "username:a")


def test_serialize_graph():
    """Graph payload serializes to JSON."""
    payload = {"nodes": [{"id": "a", "type": "username", "value": "x"}], "edges": []}
    s = serialize_graph(payload)
    assert "a" in s
    assert "username" in s
