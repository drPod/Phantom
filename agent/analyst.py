"""Analyst Claude: receives raw resolver output each turn, synthesizes a
compressed investigation brief for the planner.

Single-turn context — never accumulates history. Sees full node metadata
so it can identify correlations the planner should act on.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from anthropic import Anthropic

logger = logging.getLogger(__name__)

_MODEL = "claude-sonnet-4-6"

ANALYST_SYSTEM_PROMPT = """\
You are an OSINT data analyst. You receive raw resolver output (newly
discovered nodes with full metadata, new edges) plus a compressed summary
of the existing graph. Your job is to produce a concise investigation
brief that a planner will use to decide the next round of tool calls.

OUTPUT FORMAT — follow exactly, no preamble:

## KEY FINDINGS
- (identity correlations, security exposures, breach data, notable metadata)

## HIGH-VALUE LEADS
- entity_type:value d=depth — reason this entity is worth investigating

## LOW-VALUE / SKIP
- entity_type:value — reason to skip (disposable, generic, already covered)

## GRAPH INVENTORY
N nodes, E edges, depth range D0-Dn

RULES
• Be telegraphic: drop articles, filler words.
• Preserve ALL entity identifiers (emails, usernames, domains) verbatim.
• Highlight anything suggesting identity linkage or credential exposure.
• Collapse large lists to count + top-3 examples.
• Target ≤ {token_budget} tokens total. Ruthlessly cut low-value detail."""


def _format_raw_nodes(nodes: list[dict[str, Any]]) -> str:
    """Format raw nodes with full metadata for the analyst."""
    if not nodes:
        return "(no new nodes)"
    parts: list[str] = []
    for n in nodes:
        parts.append(json.dumps(n, default=str, indent=None, ensure_ascii=False))
    return "\n".join(parts)


def _format_raw_edges(edges: list[dict[str, Any]]) -> str:
    """Format raw edges for the analyst."""
    if not edges:
        return "(no new edges)"
    if len(edges) <= 20:
        return "\n".join(
            json.dumps(e, default=str, indent=None, ensure_ascii=False)
            for e in edges
        )
    shown = edges[:15]
    lines = [
        json.dumps(e, default=str, indent=None, ensure_ascii=False)
        for e in shown
    ]
    lines.append(f"... and {len(edges) - 15} more edges")
    return "\n".join(lines)


def call_analyst(
    client: Anthropic,
    raw_nodes: list[dict[str, Any]],
    raw_edges: list[dict[str, Any]],
    graph_summary: str,
    token_budget: int = 800,
) -> str:
    """Single-turn analyst call. Returns the brief text.

    Falls back to a minimal deterministic summary if the API call fails.
    """
    system = ANALYST_SYSTEM_PROMPT.format(token_budget=token_budget)

    user_content = (
        "NEW NODES THIS ROUND:\n"
        f"{_format_raw_nodes(raw_nodes)}\n\n"
        "NEW EDGES THIS ROUND:\n"
        f"{_format_raw_edges(raw_edges)}\n\n"
        "EXISTING GRAPH (compressed):\n"
        f"{graph_summary}"
    )

    try:
        message = client.messages.create(
            model=_MODEL,
            system=system,
            max_tokens=token_budget + 200,
            messages=[{"role": "user", "content": user_content}],
        )
        return message.content[0].text
    except Exception as e:
        logger.error("Analyst call failed, returning fallback brief: %s", e)
        return _fallback_brief(raw_nodes, raw_edges, graph_summary)


def _fallback_brief(
    raw_nodes: list[dict[str, Any]],
    raw_edges: list[dict[str, Any]],
    graph_summary: str,
) -> str:
    """Deterministic fallback when the analyst LLM call fails."""
    node_types: dict[str, int] = {}
    leads: list[str] = []
    for n in raw_nodes:
        ntype = n.get("type", "unknown")
        node_types[ntype] = node_types.get(ntype, 0) + 1
        value = n.get("value", "?")
        depth = n.get("depth", 0)
        leads.append(f"- {ntype}:{value} d={depth}")

    type_counts = ", ".join(f"{t}={c}" for t, c in sorted(node_types.items()))
    leads_text = "\n".join(leads[:10])
    if len(leads) > 10:
        leads_text += f"\n... +{len(leads) - 10} more"

    return (
        f"## KEY FINDINGS\n"
        f"[analyst unavailable — raw counts] +{len(raw_nodes)} nodes ({type_counts}), "
        f"+{len(raw_edges)} edges\n\n"
        f"## HIGH-VALUE LEADS\n{leads_text}\n\n"
        f"## GRAPH INVENTORY\n{graph_summary}"
    )
