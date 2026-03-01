"""Final report generator: one Claude call over the completed graph.

Runs after the agent loop and all post-processing (GPU extraction, breach
correlation, identity correlation) are done. Produces a structured
intelligence report that is stored in the scan result payload.

Single-turn, no history. Receives a compressed graph digest so the model
can reason over the full graph without hitting context limits.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from anthropic import Anthropic

logger = logging.getLogger(__name__)

_MODEL = "claude-sonnet-4-6"
_REPORT_MAX_TOKENS = 4096

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

REPORT_SYSTEM_PROMPT = """\
You are a senior OSINT intelligence analyst producing a final investigation \
report. You receive a compressed digest of a completed identity graph — nodes, \
edges, risk signals, and correlation findings — and must produce a \
comprehensive, actionable intelligence brief.

CRITICAL RULES
• Base ALL conclusions on evidence present in the graph data. Do NOT speculate \
beyond what the data supports.
• Cite specific entity identifiers (emails, usernames, domains) verbatim.
• Never invent breaches, platforms, or relationships not present in the data.
• If data is sparse, say so plainly rather than padding with speculation.

RISK LEVEL RUBRIC
CRITICAL — credentials_leaked=true AND breach_count ≥ 5, OR stealer log \
exposure present, OR shared_password_hash correlation found
HIGH     — breach_count ≥ 3, OR credentials_leaked=true, OR \
likely_same_person edges linking 3+ identities
MEDIUM   — breach_count 1–2, OR suspicious email reputation, OR \
shared_ip/phone correlation found
LOW      — no breach data, no credential exposure, no correlation signals
NONE     — no risk signals found

OUTPUT FORMAT — follow exactly, no preamble, no postamble:

# PHANTOM INTELLIGENCE REPORT

## EXECUTIVE SUMMARY
2–4 sentences. Who/what was investigated, key findings, overall risk level.

## IDENTITY PROFILE
Confirmed real-world attributes: name, location, employer, bio snippets. \
List only what is evidenced in the data.

## RISK ASSESSMENT
Risk level: CRITICAL / HIGH / MEDIUM / LOW / NONE
Justification: cite specific signals that drove this rating.

## CREDENTIAL EXPOSURE
Breach databases, stealer logs, paste sites. List source names, counts, \
leaked field types if known. Write "No credential exposure found." if clean.

## IDENTITY CORRELATIONS
Entities confirmed or likely to be the same person/actor. List \
likely_same_person edges and shared-pivot correlations. Write "No \
cross-entity correlations detected." if none.

## DIGITAL FOOTPRINT
Platforms confirmed, domains, notable activity patterns. Summarise \
breadth of online presence.

## RECOMMENDATIONS
3–5 actionable next steps for the investigator, ordered by priority."""


# ---------------------------------------------------------------------------
# Graph digest builder
# ---------------------------------------------------------------------------

_CORRELATION_RELATIONSHIPS = frozenset({
    "likely_same_person",
    "shared_password_hash",
    "shared_ip_address",
    "shared_phone",
})

_RISK_META_KEYS = {
    "hibp_breach_count",
    "hibp_paste_count",
    "hibp_stealer_log_domains",
    "emailrep_credentials_leaked",
    "emailrep_suspicious",
    "emailrep_reputation",
    "dehashed_total",
    "leakcheck_found",
    "identity_mismatch",
}


def _extract_risk_signals(nodes: list[dict[str, Any]]) -> list[str]:
    """Pull risk-relevant metadata fields from all nodes into a flat list."""
    signals: list[str] = []
    for node in nodes:
        meta = node.get("metadata") or {}
        nid = node.get("id", "?")

        breach_ct = meta.get("hibp_breach_count")
        if breach_ct:
            names = [b.get("name", "?") for b in (meta.get("hibp_breach_detail") or [])[:5]]
            detail = f"({','.join(names)})" if names else ""
            signals.append(f"{nid}: HIBP breaches={breach_ct}{detail}")

        paste_ct = meta.get("hibp_paste_count")
        if paste_ct:
            signals.append(f"{nid}: HIBP pastes={paste_ct}")

        stealer = meta.get("hibp_stealer_log_domains") or []
        if stealer:
            signals.append(f"{nid}: stealer_log_domains={len(stealer)} [{','.join(stealer[:5])}]")

        if meta.get("emailrep_credentials_leaked"):
            signals.append(f"{nid}: CREDENTIALS_LEAKED=true")

        if meta.get("emailrep_suspicious"):
            rep = meta.get("emailrep_reputation", "")
            signals.append(f"{nid}: SUSPICIOUS email rep={rep}")

        dehashed = meta.get("dehashed_total")
        if dehashed:
            signals.append(f"{nid}: dehashed_records={dehashed}")

        leakcheck = meta.get("leakcheck_found")
        if leakcheck:
            sources = [s.get("name", "?") for s in (meta.get("leakcheck_sources") or [])[:5]]
            signals.append(f"{nid}: leakcheck_found={leakcheck} [{','.join(sources)}]")

        if meta.get("identity_mismatch"):
            signals.append(f"{nid}: IDENTITY_MISMATCH on platform profile")

    return signals


def _extract_correlation_edges(edges: list[dict[str, Any]]) -> list[str]:
    """Return human-readable lines for all correlation/identity edges."""
    lines: list[str] = []
    for e in edges:
        rel = e.get("relationship", "")
        if rel in _CORRELATION_RELATIONSHIPS:
            conf = e.get("confidence", 1.0)
            lines.append(
                f"{e.get('source','?')} --[{rel} conf={conf:.2f}]--> {e.get('target','?')}"
            )
    return lines


def _node_type_summary(nodes: list[dict[str, Any]]) -> str:
    by_type: dict[str, int] = defaultdict(int)
    for n in nodes:
        by_type[n.get("type", "unknown")] += 1
    return ", ".join(f"{t}={c}" for t, c in sorted(by_type.items()))


def _compress_node_for_report(node: dict[str, Any]) -> str:
    """One-line compressed representation of a node for the report context."""
    nid = node.get("id", "?")
    depth = node.get("depth", 0)
    meta = node.get("metadata") or {}

    parts: list[str] = [f"{nid} d={depth}"]

    # Identity attributes
    for key in ("name", "login", "bio", "company", "location"):
        val = meta.get(key)
        if val and isinstance(val, str):
            parts.append(f'{key}="{val[:60]}"')

    # Platform presence
    hits = meta.get("hits_count")
    checked = meta.get("sites_checked")
    if hits is not None and checked is not None:
        profiles = meta.get("confirmed_profiles") or []
        site_names = [p.get("site_name", "?") for p in profiles[:5]]
        parts.append(f"platforms={hits}/{checked}[{','.join(site_names)}]")

    # GitHub
    repos = meta.get("public_repos")
    followers = meta.get("followers")
    if repos is not None:
        parts.append(f"repos={repos}")
    if followers is not None:
        parts.append(f"followers={followers}")

    # Keybase
    kb = meta.get("keybase_username")
    if kb:
        linked = meta.get("keybase_linked_accounts") or []
        services = [a.get("service", "?") for a in linked[:5]]
        parts.append(f"keybase={kb}[{','.join(services)}]")

    # Email reputation
    rep = meta.get("emailrep_reputation")
    if rep:
        parts.append(f"rep={rep}")

    return " | ".join(parts)


def _build_graph_digest(
    graph_payload: dict[str, Any],
    seed_entity: dict[str, Any],
    entities_seen: int,
    depth_reached: int,
) -> tuple[str, list[str], list[str]]:
    """
    Build a compressed, structured digest of the completed graph.

    Returns (digest_text, risk_signals, correlation_lines).
    """
    nodes: list[dict[str, Any]] = graph_payload.get("nodes", [])
    edges: list[dict[str, Any]] = graph_payload.get("edges", [])

    # Header
    header = (
        f"Seed: {seed_entity.get('type','?')}:{seed_entity.get('value','?')}\n"
        f"Total: {len(nodes)} nodes, {len(edges)} edges | "
        f"entities_seen={entities_seen}, depth_reached={depth_reached}\n"
        f"Node types: {_node_type_summary(nodes)}"
    )

    # Nodes by type, compressed
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for n in nodes:
        by_type[n.get("type", "unknown")].append(n)

    type_order = ["username", "email", "domain", "platform_profile",
                  "phone", "wallet", "ip"]
    ordered = [t for t in type_order if t in by_type]
    ordered += sorted(set(by_type.keys()) - set(type_order))

    sections: list[str] = [header]
    for ntype in ordered:
        type_nodes = by_type[ntype]
        lines = [f"--- {ntype.upper()} ({len(type_nodes)}) ---"]
        for node in type_nodes:
            lines.append(_compress_node_for_report(node))
        sections.append("\n".join(lines))

    # Edge relationship summary (non-correlation)
    rel_counts: dict[str, int] = defaultdict(int)
    for e in edges:
        rel = e.get("relationship", "linked_to")
        if rel not in _CORRELATION_RELATIONSHIPS:
            rel_counts[rel] += 1
    if rel_counts:
        edge_summary = " | ".join(
            f"{rel}={cnt}" for rel, cnt in sorted(rel_counts.items(), key=lambda x: -x[1])[:10]
        )
        sections.append(f"--- EDGE RELATIONSHIPS ---\n{edge_summary}")

    digest = "\n\n".join(sections)
    risk_signals = _extract_risk_signals(nodes)
    correlation_lines = _extract_correlation_edges(edges)

    return digest, risk_signals, correlation_lines


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_report(
    client: Anthropic,
    graph_payload: dict[str, Any],
    seed_entity: dict[str, Any],
    scan_config: dict[str, Any],
    entities_seen: int,
    depth_reached: int,
) -> str:
    """Generate a final intelligence report over the completed graph.

    Single-turn call. Falls back to a deterministic summary if the API fails.
    """
    nodes = graph_payload.get("nodes", [])
    edges = graph_payload.get("edges", [])

    if not nodes:
        return _fallback_report(graph_payload, seed_entity, entities_seen, depth_reached)

    digest, risk_signals, correlation_lines = _build_graph_digest(
        graph_payload, seed_entity, entities_seen, depth_reached
    )

    # Build the user message with clearly delimited sections
    risk_block = (
        "\n".join(risk_signals) if risk_signals else "No risk signals detected."
    )
    corr_block = (
        "\n".join(correlation_lines) if correlation_lines else "No correlation edges found."
    )

    user_content = (
        "---SEED---\n"
        f"type={seed_entity.get('type','?')} value={seed_entity.get('value','?')}\n\n"
        "---SCAN CONFIG---\n"
        f"max_entities={scan_config.get('max_entities','?')} "
        f"max_depth={scan_config.get('max_depth','?')} "
        f"timeout_minutes={scan_config.get('timeout_minutes','?')}\n\n"
        "---GRAPH DIGEST---\n"
        f"{digest}\n\n"
        "---RISK SIGNALS---\n"
        f"{risk_block}\n\n"
        "---IDENTITY CORRELATIONS---\n"
        f"{corr_block}\n\n"
        "Generate the intelligence report now."
    )

    try:
        message = client.messages.create(
            model=_MODEL,
            system=[
                {
                    "type": "text",
                    "text": REPORT_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            max_tokens=_REPORT_MAX_TOKENS,
            messages=[{"role": "user", "content": user_content}],
        )
        return message.content[0].text
    except Exception as e:
        logger.error("Report generation failed, returning fallback: %s", e)
        return _fallback_report(graph_payload, seed_entity, entities_seen, depth_reached)


# ---------------------------------------------------------------------------
# Deterministic fallback
# ---------------------------------------------------------------------------

def _fallback_report(
    graph_payload: dict[str, Any],
    seed_entity: dict[str, Any],
    entities_seen: int,
    depth_reached: int,
) -> str:
    nodes: list[dict[str, Any]] = graph_payload.get("nodes", [])
    edges: list[dict[str, Any]] = graph_payload.get("edges", [])

    type_summary = _node_type_summary(nodes)
    risk_signals = _extract_risk_signals(nodes)
    correlation_lines = _extract_correlation_edges(edges)

    seed_str = f"{seed_entity.get('type','?')}:{seed_entity.get('value','?')}"

    risk_section = "\n".join(f"- {s}" for s in risk_signals) if risk_signals else "- No risk signals detected."
    corr_section = "\n".join(f"- {c}" for c in correlation_lines) if correlation_lines else "- No correlation edges found."

    return (
        "# PHANTOM INTELLIGENCE REPORT\n\n"
        "## EXECUTIVE SUMMARY\n"
        f"Investigation of {seed_str} completed. "
        f"Graph contains {len(nodes)} nodes and {len(edges)} edges across "
        f"{entities_seen} entities at depth {depth_reached}. "
        "[Report generation unavailable — deterministic summary follows.]\n\n"
        "## IDENTITY PROFILE\n"
        f"Seed entity: {seed_str}\n"
        f"Node breakdown: {type_summary}\n\n"
        "## RISK ASSESSMENT\n"
        f"Risk level: {'HIGH' if risk_signals else 'UNKNOWN'}\n"
        f"Signals found: {len(risk_signals)}\n\n"
        "## CREDENTIAL EXPOSURE\n"
        f"{risk_section}\n\n"
        "## IDENTITY CORRELATIONS\n"
        f"{corr_section}\n\n"
        "## DIGITAL FOOTPRINT\n"
        f"{len(nodes)} entities discovered across {depth_reached} hops.\n\n"
        "## RECOMMENDATIONS\n"
        "- Review risk signals listed above manually.\n"
        "- Investigate identity correlation edges for account linkage.\n"
        "- Re-run scan with increased depth/entity limits if needed.\n"
    )
