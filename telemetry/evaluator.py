"""Telemetry evaluator — takes a telemetry bundle produced by
``TelemetryCollector`` and uses an LLM call (Claude claude-sonnet-4-6) with a
detailed rubric prompt to produce a structured evaluation scorecard.

The scorecard grades five dimensions:
  (a) planner efficiency
  (b) analyst brief quality
  (c) resolver ROI
  (d) investigation completeness
  (e) report quality

Results are cached in a Modal Dict so repeated requests don't re-run the LLM.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import defaultdict
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)

_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 4096
EVAL_DICT_NAME = "osint-telemetry-eval"

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ResolverROI(BaseModel):
    resolver_name: str
    calls: int
    successes: int
    failures: int
    failure_rate: float
    entities_discovered_per_call: float


class CategoryScore(BaseModel):
    score: int
    grade: str
    findings: list[str]
    suggestions: list[str]


class EvaluationScorecard(BaseModel):
    scan_id: str
    evaluated_at: float
    overall_score: int
    overall_grade: str
    planner_efficiency: CategoryScore
    analyst_brief_quality: CategoryScore
    resolver_roi: CategoryScore
    investigation_completeness: CategoryScore
    report_quality: CategoryScore
    resolver_breakdown: list[ResolverROI]
    summary: str


# ---------------------------------------------------------------------------
# Deterministic pre-computation
# ---------------------------------------------------------------------------


def _precompute_metrics(bundle: dict[str, Any]) -> dict[str, Any]:
    """Extract deterministic metrics from the telemetry bundle before the LLM
    call so the model has concrete numbers to reason over."""

    resolvers: list[dict[str, Any]] = bundle.get("resolvers", [])
    planner_turns: list[dict[str, Any]] = bundle.get("planner_turns", [])
    analyst_briefs: list[dict[str, Any]] = bundle.get("analyst_briefs", [])

    # --- Resolver stats per resolver name ---
    by_resolver: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"calls": 0, "successes": 0, "failures": 0, "entity_keys": set()}
    )
    for r in resolvers:
        name = r.get("resolver_name", "unknown")
        by_resolver[name]["calls"] += 1
        if r.get("succeeded"):
            by_resolver[name]["successes"] += 1
        else:
            by_resolver[name]["failures"] += 1
        by_resolver[name]["entity_keys"].add(r.get("entity_key", ""))

    resolver_breakdown: list[dict[str, Any]] = []
    for name, stats in sorted(by_resolver.items()):
        calls = stats["calls"]
        resolver_breakdown.append({
            "resolver_name": name,
            "calls": calls,
            "successes": stats["successes"],
            "failures": stats["failures"],
            "failure_rate": round(stats["failures"] / calls, 3) if calls else 0.0,
            "unique_entities": len(stats["entity_keys"]),
        })

    # --- Duplicate resolver calls (same resolver + same entity_key) ---
    seen_pairs: set[tuple[str, str]] = set()
    duplicate_calls: list[dict[str, str]] = []
    for r in resolvers:
        pair = (r.get("resolver_name", ""), r.get("entity_key", ""))
        if pair in seen_pairs:
            duplicate_calls.append({"resolver": pair[0], "entity_key": pair[1]})
        seen_pairs.add(pair)

    # --- Planner stats ---
    total_tool_calls = sum(len(t.get("tool_calls", [])) for t in planner_turns)

    # --- Scan duration ---
    started = bundle.get("started_at")
    finished = bundle.get("finished_at")
    duration_s = round(finished - started, 1) if started and finished else None

    # --- Graph summary ---
    gs = bundle.get("graph_summary") or {}

    return {
        "resolver_breakdown": resolver_breakdown,
        "duplicate_calls": duplicate_calls,
        "total_resolver_calls": len(resolvers),
        "total_resolver_successes": sum(1 for r in resolvers if r.get("succeeded")),
        "total_resolver_failures": sum(1 for r in resolvers if not r.get("succeeded")),
        "total_planner_turns": len(planner_turns),
        "total_tool_calls_issued": total_tool_calls,
        "total_analyst_briefs": len(analyst_briefs),
        "total_new_nodes_from_briefs": sum(b.get("new_nodes", 0) for b in analyst_briefs),
        "total_new_edges_from_briefs": sum(b.get("new_edges", 0) for b in analyst_briefs),
        "graph_node_count": gs.get("node_count", 0),
        "graph_edge_count": gs.get("edge_count", 0),
        "scan_duration_seconds": duration_s,
        "user_stopped": bundle.get("user_stopped", False),
        "final_status": bundle.get("final_status"),
        "error_count": len(bundle.get("errors", [])),
    }


# ---------------------------------------------------------------------------
# Rubric system prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert evaluator of AI-driven OSINT investigation workflows. You \
receive a telemetry bundle from a completed scan and pre-computed metrics. \
Your job is to produce a structured evaluation scorecard as JSON.

GRADING SCALE (applies to every category):
  10  = flawless
  8-9 = excellent, minor issues only
  6-7 = good, some room for improvement
  4-5 = mediocre, significant issues
  2-3 = poor, major problems
  1   = fundamentally broken

LETTER GRADES: A (9-10), B (7-8), C (5-6), D (3-4), F (1-2)

CATEGORY RUBRICS:

(a) PLANNER EFFICIENCY
- Redundant resolver calls: same (resolver_name, entity_key) called more than \
once is always wasteful. Penalise proportionally to the number of duplicates.
- Batching: the planner should issue ALL actionable leads in a single turn. If \
analyst briefs surface N high-value leads but the planner only dispatches <N \
tool calls in that turn, it serialised unnecessarily.
- Prompt action: high-value leads from analyst briefs should be acted on in the \
immediately following planner turn, not deferred.
- TIER 3 discipline: low-value / skip entities from analyst briefs should NOT \
be investigated. Penalise if they were.

(b) ANALYST BRIEF QUALITY
- Did the briefs correctly surface entities the planner subsequently acted on?
- Were HIGH-VALUE LEADS sections populated with actionable items?
- Did the analyst flag identity mismatches and low-value entities?
- Was the brief format consistent (KEY FINDINGS, HIGH-VALUE LEADS, LOW-VALUE / \
SKIP, GRAPH INVENTORY)?
- Did briefs avoid hallucinating entities not present in resolver output?

(c) RESOLVER ROI
- Entities discovered per resolver call (use new_nodes from analyst briefs \
following each resolver batch as a proxy). Higher is better.
- Failure rate per resolver and overall. >30% failure rate is concerning.
- Were expensive/slow resolvers used on high-value targets (not wasted on \
low-value entities)?
- Wasted calls: resolver calls that returned zero new entities.

(d) INVESTIGATION COMPLETENESS
- Did the scan reach dead-ends prematurely? Look for high-value leads in \
analyst briefs that were never acted on by the planner.
- Did it over-explore low-value branches (TIER 3 entities investigated)?
- Was depth budget used effectively (did it reach max_depth or stop short)?
- Was correlate_identities called when there were 5+ same-type nodes?
- If user_stopped=true, note this but don't penalise the system for it.

(e) REPORT QUALITY
- Does the report cover all discovered entity types present in graph_summary?
- Are risk signals (breaches, credential leaks) reflected in the report?
- Are recommendations actionable and specific (not generic boilerplate)?
- Is the report well-structured with the expected sections (EXECUTIVE SUMMARY, \
IDENTITY PROFILE, RISK ASSESSMENT, CREDENTIAL EXPOSURE, IDENTITY CORRELATIONS, \
DIGITAL FOOTPRINT, RECOMMENDATIONS)?
- If report is null/empty, score 1.

OUTPUT FORMAT — respond with ONLY valid JSON matching this exact schema, no \
markdown fences, no preamble, no postamble:

{
  "overall_score": <int 1-10>,
  "overall_grade": "<A|B|C|D|F>",
  "planner_efficiency": {
    "score": <int 1-10>,
    "grade": "<A|B|C|D|F>",
    "findings": ["<finding1>", ...],
    "suggestions": ["<suggestion1>", ...]
  },
  "analyst_brief_quality": {
    "score": <int 1-10>,
    "grade": "<A|B|C|D|F>",
    "findings": ["<finding1>", ...],
    "suggestions": ["<suggestion1>", ...]
  },
  "resolver_roi": {
    "score": <int 1-10>,
    "grade": "<A|B|C|D|F>",
    "findings": ["<finding1>", ...],
    "suggestions": ["<suggestion1>", ...]
  },
  "investigation_completeness": {
    "score": <int 1-10>,
    "grade": "<A|B|C|D|F>",
    "findings": ["<finding1>", ...],
    "suggestions": ["<suggestion1>", ...]
  },
  "report_quality": {
    "score": <int 1-10>,
    "grade": "<A|B|C|D|F>",
    "findings": ["<finding1>", ...],
    "suggestions": ["<suggestion1>", ...]
  },
  "resolver_breakdown": [
    {
      "resolver_name": "<name>",
      "calls": <int>,
      "successes": <int>,
      "failures": <int>,
      "failure_rate": <float 0-1>,
      "entities_discovered_per_call": <float>
    },
    ...
  ],
  "summary": "<2-4 sentence overall assessment>"
}

RULES:
- Base scores ONLY on evidence in the telemetry data. Do not speculate.
- Each findings list should have 2-5 concrete observations.
- Each suggestions list should have 1-3 actionable improvements.
- resolver_breakdown must include every resolver that appears in the data.
- entities_discovered_per_call is your best estimate from the telemetry \
(use new_nodes from analyst briefs as a proxy, distributed across resolvers).
- The overall_score should be the weighted average: planner_efficiency 25%, \
resolver_roi 20%, investigation_completeness 25%, analyst_brief_quality 15%, \
report_quality 15%."""


# ---------------------------------------------------------------------------
# Bundle formatting for the user message
# ---------------------------------------------------------------------------


def _extract_leads_from_brief(brief_text: str) -> str:
    """Extract only the HIGH-VALUE LEADS and LOW-VALUE/SKIP sections from an
    analyst brief, discarding verbose KEY FINDINGS and GRAPH INVENTORY prose.

    Returns a compact string with just those two sections, or a short fallback
    if neither section is found.
    """
    if not brief_text:
        return "(empty brief)"

    # Patterns that mark the start of each section we want to keep.
    # Analyst briefs use headers like "HIGH-VALUE LEADS", "LOW-VALUE / SKIP",
    # "LOW-VALUE/SKIP", etc.
    wanted_pattern = re.compile(
        r"(HIGH[- ]VALUE LEADS?|LOW[- ]VALUE\s*/\s*SKIP)",
        re.IGNORECASE,
    )
    # Patterns that mark the start of sections we want to drop so we know
    # where a wanted section ends.
    section_header = re.compile(
        r"^(KEY FINDINGS|GRAPH INVENTORY|IDENTITY CORRELAT|EXECUTIVE|RISK|CREDENTIAL|DIGITAL|RECOMMENDATION)",
        re.IGNORECASE | re.MULTILINE,
    )

    lines = brief_text.splitlines()
    kept: list[str] = []
    in_wanted = False

    for line in lines:
        if wanted_pattern.search(line):
            in_wanted = True
            kept.append(line)
        elif in_wanted:
            # Stop capturing if we hit a different top-level section header
            if section_header.match(line.strip()):
                in_wanted = False
            else:
                kept.append(line)

    result = "\n".join(kept).strip()
    if not result:
        # Fall back to a short truncation of the whole brief so we still have
        # something for the LLM to work with.
        return _truncate(brief_text, 300)
    return result


def _format_bundle_for_prompt(
    bundle: dict[str, Any],
    metrics: dict[str, Any],
) -> str:
    """Build a compact user message for the evaluator LLM.

    The pre-computed metrics already carry all quantitative signal.  This
    function adds only the qualitative signal that cannot be reduced to
    numbers, keeping the total message well under 8K tokens even for large
    scans.
    """
    sections: list[str] = []

    # --- Seed, config, status (tiny) ---
    sections.append(
        "---SEED ENTITY---\n"
        f"{json.dumps(bundle.get('seed_entity', {}), default=str)}"
    )
    sections.append(
        "---SCAN CONFIG---\n"
        f"{json.dumps(bundle.get('config', {}), default=str)}"
    )
    sections.append(
        "---SCAN STATUS---\n"
        f"final_status={bundle.get('final_status')} "
        f"user_stopped={bundle.get('user_stopped')} "
        f"errors={len(bundle.get('errors', []))}"
    )

    # --- Pre-computed metrics (already compact) ---
    sections.append(
        "---PRE-COMPUTED METRICS---\n"
        f"{json.dumps(metrics, indent=2, default=str)}"
    )

    # --- Planner turns: one line per turn, no reasoning text ---
    # The rubric judges the planner by its actions (which tools, batching,
    # duplicates), not by its internal monologue.
    turns = bundle.get("planner_turns", [])
    turn_lines: list[str] = []
    for t in turns:
        tool_names = [tc.get("name", "?") for tc in t.get("tool_calls", [])]
        turn_lines.append(
            f"Turn {t.get('turn')}: "
            f"tools=[{', '.join(tool_names) or 'none'}] "
            f"stop={t.get('stop_reason')}"
        )
    sections.append("---PLANNER TURNS---\n" + "\n".join(turn_lines))

    # --- Analyst briefs: leads sections only, not full prose ---
    briefs = bundle.get("analyst_briefs", [])
    brief_blocks: list[str] = []
    for b in briefs:
        leads = _extract_leads_from_brief(b.get("brief", ""))
        brief_blocks.append(
            f"Turn {b.get('turn')} bg={b.get('background')} "
            f"+{b.get('new_nodes')}n +{b.get('new_edges')}e\n"
            f"{leads}"
        )
    sections.append("---ANALYST BRIEFS (leads only)---\n" + "\n---\n".join(brief_blocks))

    # --- Resolver calls: failures + duplicates only ---
    # Successful calls are already summarised in pre-computed metrics.
    failed_calls: list[str] = []
    for r in bundle.get("resolvers", []):
        if not r.get("succeeded"):
            failed_calls.append(
                f"{r.get('resolver_name')} entity={r.get('entity_key')} "
                f"err={r.get('error') or 'unknown'}"
            )
    failed_section = "\n".join(failed_calls) if failed_calls else "(none)"
    sections.append(f"---FAILED RESOLVER CALLS---\n{failed_section}")

    # --- Graph summary ---
    gs = bundle.get("graph_summary") or {}
    sections.append(
        "---GRAPH SUMMARY---\n"
        f"{json.dumps(gs, default=str)}"
    )

    # --- Report (structural check only; 1500 chars is enough) ---
    report = bundle.get("report") or "(no report generated)"
    sections.append(
        "---FINAL REPORT---\n"
        f"{_truncate(report, 1500)}"
    )

    sections.append("Produce the evaluation scorecard JSON now.")

    return "\n\n".join(sections)


def _truncate(text: str | None, max_len: int) -> str:
    if not text:
        return "(empty)"
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"... [truncated, {len(text)} chars total]"


# ---------------------------------------------------------------------------
# JSON extraction helper
# ---------------------------------------------------------------------------


def _extract_json(text: str) -> dict[str, Any]:
    """Extract a JSON object from the LLM response, handling optional markdown
    fences or leading/trailing text."""
    # Try stripping markdown fences first
    fenced = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
    if fenced:
        return json.loads(fenced.group(1))
    # Try finding the outermost { ... }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(text[start : end + 1])
    return json.loads(text)


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------


def evaluate_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a telemetry bundle and return the scorecard as a dict.

    Performs a single LLM call with the rubric prompt. Returns a dict
    matching the ``EvaluationScorecard`` schema.
    """
    from anthropic import Anthropic

    scan_id = bundle.get("scan_id", "unknown")
    metrics = _precompute_metrics(bundle)
    user_message = _format_bundle_for_prompt(bundle, metrics)

    client = Anthropic()

    try:
        message = client.messages.create(
            model=_MODEL,
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            max_tokens=_MAX_TOKENS,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_text = message.content[0].text
    except Exception:
        logger.exception("Evaluation LLM call failed for scan %s", scan_id)
        raise

    try:
        raw_scorecard = _extract_json(raw_text)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error(
            "Failed to parse evaluation JSON for scan %s: %s\nRaw: %s",
            scan_id, exc, raw_text[:500],
        )
        raise ValueError(f"LLM returned invalid JSON: {exc}") from exc

    raw_scorecard["scan_id"] = scan_id
    raw_scorecard["evaluated_at"] = time.time()

    scorecard = EvaluationScorecard.model_validate(raw_scorecard)
    return scorecard.model_dump()
