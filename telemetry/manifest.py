"""Agent manifest generator — produces a self-describing document that external
AI agents (OpenClaw, Cursor agents) can consume to understand the project
structure, current prompt texts, tool schemas, and the latest improvement
proposals.

The manifest is generated on demand (not cached) so it always reflects the
current state of the codebase.  Prompt texts are read from the live module
constants so any in-place edits are immediately reflected.

Also defines ``WebhookPayload`` and ``WebhookResponse`` Pydantic models used
by the ``POST /telemetry/webhook`` endpoint in ``api.py``.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Literal

from pydantic import BaseModel

WEBHOOK_DICT_NAME = "osint-agent-webhooks"
MANIFEST_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Manifest models
# ---------------------------------------------------------------------------


class FileRole(BaseModel):
    path: str
    role: str
    key_exports: list[str]


class PromptSnapshot(BaseModel):
    name: str
    source_file: str
    text: str


class AgentManifest(BaseModel):
    generated_at: float
    version: str
    project_structure: list[FileRole]
    prompts: list[PromptSnapshot]
    tool_schemas: list[dict[str, Any]]
    latest_proposals: dict[str, Any] | None


# ---------------------------------------------------------------------------
# Webhook models
# ---------------------------------------------------------------------------


class WebhookPayload(BaseModel):
    agent_id: str
    proposal_target_file: str
    proposal_section: str
    patch_description: str
    result: Literal["success", "failure", "partial"]
    details: str | None = None
    applied_at: float | None = None


class WebhookResponse(BaseModel):
    ok: bool
    logged_id: str


# ---------------------------------------------------------------------------
# Project structure map (hardcoded; stable contract for external agents)
# ---------------------------------------------------------------------------

_PROJECT_STRUCTURE: list[dict[str, Any]] = [
    {
        "path": "orchestrator.py",
        "role": "Main scan orchestrator — runs the planner–analyst agent loop, spawns resolvers via Modal, drives GPU post-processing and report generation.",
        "key_exports": ["run_scan", "InFlightPool"],
    },
    {
        "path": "api.py",
        "role": "FastAPI ASGI app — all REST endpoints for scan lifecycle, graph, report, telemetry, evaluation, proposals, manifest, and webhook.",
        "key_exports": ["fastapi_app"],
    },
    {
        "path": "models.py",
        "role": "Pydantic data models shared across the project.",
        "key_exports": [
            "Entity", "Node", "Edge", "ScanConfig", "ScanRequest",
            "ScanResponse", "StatusResponse", "GraphResponse", "ScanStatus",
        ],
    },
    {
        "path": "app.py",
        "role": "Modal app definition — image build, secrets, and module registration.",
        "key_exports": ["app", "image", "osint_secret"],
    },
    {
        "path": "graph.py",
        "role": "NetworkX graph construction from scan-state dicts.",
        "key_exports": ["build_from_dict"],
    },
    {
        "path": "stream.py",
        "role": "SSE event writer — appends events to the per-scan Modal Dict stream.",
        "key_exports": ["write_event"],
    },
    {
        "path": "scan_log.py",
        "role": "Per-scan activity log — appends and loads structured event records.",
        "key_exports": ["append_activity", "load_activity_log"],
    },
    {
        "path": "agent/planner.py",
        "role": "Planner LLM agent — receives analyst briefs, emits tool_use blocks selecting resolver calls.",
        "key_exports": [
            "PLANNER_SYSTEM_PROMPT", "_EMAIL_CONTEXT_BLOCK",
            "format_system_prompt", "call_planner",
        ],
    },
    {
        "path": "agent/analyst.py",
        "role": "Analyst LLM agent — single-turn; synthesises raw resolver output into a compressed investigation brief.",
        "key_exports": ["ANALYST_SYSTEM_PROMPT", "call_analyst"],
    },
    {
        "path": "agent/report.py",
        "role": "Final report generator — single-turn Claude call over the completed graph digest.",
        "key_exports": ["REPORT_SYSTEM_PROMPT", "generate_report"],
    },
    {
        "path": "agent/tools.py",
        "role": "Anthropic tool_use schema definitions for all OSINT resolvers.",
        "key_exports": [
            "RESOLVER_TOOLS", "ALL_TOOLS", "TOOL_NAME_TO_RESOLVER",
            "RESOLVE_GITHUB", "ENUMERATE_USERNAME", "RESOLVE_SOCIAL",
            "RESOLVE_EMAIL", "RESOLVE_BREACH", "RESOLVE_DOMAIN",
            "RESOLVE_PHONE", "RESOLVE_WALLET",
            "CORRELATE_IDENTITIES", "FINISH_INVESTIGATION",
        ],
    },
    {
        "path": "agent/state.py",
        "role": "Graph state tracking — diffs between turns, compressed graph summary for prompts.",
        "key_exports": ["GraphState"],
    },
    {
        "path": "telemetry/exporter.py",
        "role": "TelemetryCollector — incrementally records scan events and flushes to Modal Dict.",
        "key_exports": ["TelemetryCollector", "TELEMETRY_DICT_NAME"],
    },
    {
        "path": "telemetry/evaluator.py",
        "role": "LLM-based scan evaluator — grades five categories (planner efficiency, analyst brief quality, resolver ROI, investigation completeness, report quality) and produces a structured scorecard.",
        "key_exports": ["evaluate_bundle", "EVAL_DICT_NAME", "EvaluationScorecard"],
    },
    {
        "path": "telemetry/proposer.py",
        "role": "Improvement proposal generator — aggregates N scorecards and uses an LLM to produce diff-ready proposals targeting specific files and sections.",
        "key_exports": ["generate_proposals", "PROPOSALS_DICT_NAME", "ImprovementProposal", "ProposalReport"],
    },
    {
        "path": "telemetry/manifest.py",
        "role": "Agent manifest generator — produces this self-describing document. Also defines WebhookPayload/WebhookResponse for the POST /telemetry/webhook endpoint.",
        "key_exports": ["generate_manifest", "WebhookPayload", "WebhookResponse", "WEBHOOK_DICT_NAME"],
    },
    {
        "path": "resolvers/username.py",
        "role": "GitHub profile resolver — lightweight probe for public email, blog URL, bio.",
        "key_exports": ["resolve_github"],
    },
    {
        "path": "resolvers/username_enum.py",
        "role": "Username enumerator — WhatsMyName ~600-site existence check.",
        "key_exports": ["enumerate_username"],
    },
    {
        "path": "resolvers/social.py",
        "role": "Deep social resolver — Reddit, Keybase, Hacker News, Stack Overflow, PGP.",
        "key_exports": ["resolve_social"],
    },
    {
        "path": "resolvers/email.py",
        "role": "Email enrichment resolver — Kickbox, Hunter, Gravatar, EmailRep, HIBP.",
        "key_exports": ["resolve_email"],
    },
    {
        "path": "resolvers/breach.py",
        "role": "Breach database resolver — Dehashed, LeakCheck, BreachDirectory.",
        "key_exports": ["resolve_breach"],
    },
    {
        "path": "resolvers/domain.py",
        "role": "Domain intelligence resolver — crt.sh, DNS, WHOIS, SecurityTrails, Hunter.",
        "key_exports": ["resolve_domain"],
    },
    {
        "path": "resolvers/phone.py",
        "role": "Phone number resolver — Numverify and Veriphone carrier/geo lookup.",
        "key_exports": ["resolve_phone"],
    },
    {
        "path": "resolvers/wallet.py",
        "role": "Cryptocurrency wallet resolver — Etherscan (ETH/ERC-20) and Blockchain.com (BTC).",
        "key_exports": ["resolve_wallet"],
    },
    {
        "path": "resolvers/identity_correlator.py",
        "role": "GPU-backed cross-platform identity correlation — emits likely_same_person edges.",
        "key_exports": ["correlate_identities_tool"],
    },
    {
        "path": "inference/extractor.py",
        "role": "GPU entity extractor — Qwen2.5-1.5B post-processing over node metadata.",
        "key_exports": ["extract_entities"],
    },
    {
        "path": "frontend/index.html",
        "role": "D3.js force-directed graph UI with SSE polling for live scan updates.",
        "key_exports": [],
    },
]


# ---------------------------------------------------------------------------
# Prompt collection
# ---------------------------------------------------------------------------


def _collect_prompts() -> list[dict[str, Any]]:
    """Import prompt constants from live modules and return as snapshots.

    Each import is done inside the function to avoid circular-import issues
    at module load time.  Failures are caught per-prompt so a broken import
    in one module doesn't prevent the rest from being collected.
    """
    snapshots: list[dict[str, Any]] = []

    _sources: list[tuple[str, str, str]] = [
        ("planner_system_prompt", "agent/planner.py", "agent.planner.PLANNER_SYSTEM_PROMPT"),
        ("analyst_system_prompt", "agent/analyst.py", "agent.analyst.ANALYST_SYSTEM_PROMPT"),
        ("report_system_prompt", "agent/report.py", "agent.report.REPORT_SYSTEM_PROMPT"),
        ("evaluator_rubric_prompt", "telemetry/evaluator.py", "telemetry.evaluator._SYSTEM_PROMPT"),
        ("proposer_instructions_prompt", "telemetry/proposer.py", "telemetry.proposer._SYSTEM_PROMPT"),
    ]

    for name, source_file, dotted_path in _sources:
        try:
            module_path, attr = dotted_path.rsplit(".", 1)
            import importlib
            mod = importlib.import_module(module_path)
            text = getattr(mod, attr)
            snapshots.append({"name": name, "source_file": source_file, "text": text})
        except Exception as exc:
            snapshots.append({
                "name": name,
                "source_file": source_file,
                "text": f"[unavailable: {exc}]",
            })

    return snapshots


# ---------------------------------------------------------------------------
# Tool schema collection
# ---------------------------------------------------------------------------


def _collect_tool_schemas() -> list[dict[str, Any]]:
    """Return ALL_TOOLS from agent/tools.py."""
    try:
        from agent.tools import ALL_TOOLS
        return list(ALL_TOOLS)
    except Exception as exc:
        return [{"error": f"Could not load tool schemas: {exc}"}]


# ---------------------------------------------------------------------------
# Latest proposals
# ---------------------------------------------------------------------------


def _collect_latest_proposals() -> dict[str, Any] | None:
    """Try to fetch the latest proposals; return None if unavailable."""
    try:
        from telemetry.proposer import generate_proposals
        return generate_proposals(last_n=10)
    except ValueError:
        # Fewer than 3 scorecards — not enough data yet
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def generate_manifest() -> dict[str, Any]:
    """Generate and return the agent manifest as a plain dict.

    The manifest is always freshly generated (not cached) so prompt text
    changes are immediately visible to consuming agents.
    """
    manifest = AgentManifest(
        generated_at=time.time(),
        version=MANIFEST_VERSION,
        project_structure=[FileRole(**f) for f in _PROJECT_STRUCTURE],
        prompts=[PromptSnapshot(**p) for p in _collect_prompts()],
        tool_schemas=_collect_tool_schemas(),
        latest_proposals=_collect_latest_proposals(),
    )
    return manifest.model_dump()
