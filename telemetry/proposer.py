"""Telemetry proposer — aggregates N evaluation scorecards, identifies
recurring failure patterns across scans, and uses an LLM call to generate
concrete, diff-ready improvement proposals.

Each proposal targets a specific file and section in the codebase (e.g.
``agent/planner.py`` → ``PLANNER_SYSTEM_PROMPT``) and includes enough detail
to act on directly.

Results are cached in a Modal Dict keyed by a hash of the input scan IDs so
repeated requests with the same scans don't re-run the LLM.

Minimum 3 scorecards are required; a ``ValueError`` is raised otherwise.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections import Counter, defaultdict
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)

_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 4096
_MIN_SCORECARDS = 3
PROPOSALS_DICT_NAME = "osint-telemetry-proposals"

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ImprovementProposal(BaseModel):
    target_file: str
    section_description: str
    current_behavior: str
    proposed_change: str
    rationale: str
    expected_impact: str
    priority: int


class ProposalReport(BaseModel):
    generated_at: float
    scan_ids: list[str]
    scan_count: int
    aggregate_overall_score: float
    proposals: list[ImprovementProposal]


# ---------------------------------------------------------------------------
# Scorecard collection
# ---------------------------------------------------------------------------

_CATEGORIES = [
    "planner_efficiency",
    "analyst_brief_quality",
    "resolver_roi",
    "investigation_completeness",
    "report_quality",
]


def _collect_scorecards(last_n: int) -> list[dict[str, Any]]:
    """Read up to *last_n* scorecards from the eval Modal Dict, sorted by
    ``evaluated_at`` descending (most recent first)."""
    import modal

    from telemetry.evaluator import EVAL_DICT_NAME

    eval_dict = modal.Dict.from_name(EVAL_DICT_NAME, create_if_missing=True)

    scorecards: list[dict[str, Any]] = []
    try:
        for key in eval_dict.keys():
            try:
                sc = eval_dict[key]
                if isinstance(sc, dict) and "evaluated_at" in sc:
                    scorecards.append(sc)
            except Exception:
                continue
    except Exception as exc:
        logger.warning("Failed to iterate eval dict: %s", exc)

    scorecards.sort(key=lambda s: s.get("evaluated_at", 0), reverse=True)
    return scorecards[:last_n]


# ---------------------------------------------------------------------------
# Deterministic aggregation
# ---------------------------------------------------------------------------


def _aggregate_scorecards(scorecards: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute cross-scan statistics from a list of scorecards.

    Returns a dict with:
    - per-category average scores and grade distributions
    - recurring findings and suggestions (frequency-ranked)
    - per-resolver aggregate failure rates
    - weak categories (average score <= 6)
    - overall score trend
    """
    n = len(scorecards)

    # Per-category stats
    category_scores: dict[str, list[int]] = {c: [] for c in _CATEGORIES}
    category_grades: dict[str, Counter] = {c: Counter() for c in _CATEGORIES}

    # Findings and suggestions aggregated across all categories and scans
    all_findings: Counter = Counter()
    all_suggestions: Counter = Counter()

    # Per-category findings/suggestions
    category_findings: dict[str, Counter] = {c: Counter() for c in _CATEGORIES}
    category_suggestions: dict[str, Counter] = {c: Counter() for c in _CATEGORIES}

    # Resolver stats across scans
    resolver_calls: dict[str, int] = defaultdict(int)
    resolver_failures: dict[str, int] = defaultdict(int)
    resolver_successes: dict[str, int] = defaultdict(int)

    overall_scores: list[int] = []

    for sc in scorecards:
        overall_scores.append(sc.get("overall_score", 0))

        for cat in _CATEGORIES:
            cat_data = sc.get(cat, {})
            score = cat_data.get("score")
            if score is not None:
                category_scores[cat].append(score)
            grade = cat_data.get("grade")
            if grade:
                category_grades[cat][grade] += 1

            for finding in cat_data.get("findings", []):
                all_findings[finding] += 1
                category_findings[cat][finding] += 1
            for suggestion in cat_data.get("suggestions", []):
                all_suggestions[suggestion] += 1
                category_suggestions[cat][suggestion] += 1

        for rb in sc.get("resolver_breakdown", []):
            name = rb.get("resolver_name", "unknown")
            resolver_calls[name] += rb.get("calls", 0)
            resolver_failures[name] += rb.get("failures", 0)
            resolver_successes[name] += rb.get("successes", 0)

    # Build category summary
    category_summary: list[dict[str, Any]] = []
    weak_categories: list[str] = []
    for cat in _CATEGORIES:
        scores = category_scores[cat]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        if avg <= 6.0:
            weak_categories.append(cat)
        top_findings = [
            {"text": text, "frequency": freq}
            for text, freq in category_findings[cat].most_common(5)
            if freq >= 2
        ]
        top_suggestions = [
            {"text": text, "frequency": freq}
            for text, freq in category_suggestions[cat].most_common(3)
            if freq >= 2
        ]
        category_summary.append({
            "category": cat,
            "average_score": avg,
            "grade_distribution": dict(category_grades[cat]),
            "recurring_findings": top_findings,
            "recurring_suggestions": top_suggestions,
        })

    # Resolver aggregate
    resolver_summary: list[dict[str, Any]] = []
    for name in sorted(resolver_calls):
        calls = resolver_calls[name]
        failures = resolver_failures[name]
        resolver_summary.append({
            "resolver_name": name,
            "total_calls": calls,
            "total_failures": failures,
            "aggregate_failure_rate": round(failures / calls, 3) if calls else 0.0,
        })

    # High-frequency cross-category findings (appear in >50% of scans)
    threshold = max(2, n // 2)
    cross_scan_findings = [
        {"text": text, "frequency": freq, "pct_scans": round(freq / n * 100)}
        for text, freq in all_findings.most_common(15)
        if freq >= threshold
    ]
    cross_scan_suggestions = [
        {"text": text, "frequency": freq, "pct_scans": round(freq / n * 100)}
        for text, freq in all_suggestions.most_common(10)
        if freq >= threshold
    ]

    avg_overall = round(sum(overall_scores) / n, 2) if overall_scores else 0.0

    return {
        "scan_count": n,
        "average_overall_score": avg_overall,
        "overall_scores": overall_scores,
        "category_summary": category_summary,
        "weak_categories": weak_categories,
        "resolver_aggregate": resolver_summary,
        "cross_scan_findings": cross_scan_findings,
        "cross_scan_suggestions": cross_scan_suggestions,
    }


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert software engineer and AI systems architect. You have been \
given aggregated evaluation data from N completed OSINT investigation scans \
run by an AI agent system. Your job is to analyse recurring failure patterns \
and generate concrete, diff-ready improvement proposals for the codebase.

CODEBASE MAP — files you may target with proposals:

  agent/planner.py
    • PLANNER_SYSTEM_PROMPT — the multi-section system prompt for the planner \
LLM. Sections: PARALLELISM RULE, PRIORITY REASONING (TIER 1/2/3), IDENTITY \
COHERENCE, IDENTITY CORRELATOR, DEPTH PARAMETER, LIMITS, WHEN TO STOP, \
RESPONSE STYLE.
    • _EMAIL_CONTEXT_BLOCK — optional block appended when a seed email is known.
    • format_system_prompt() — builds the final prompt with max_depth, \
max_entities, scan_id substituted in.
    • call_planner() — Anthropic API call wrapper.

  agent/tools.py
    • Tool schema dicts: RESOLVE_GITHUB, ENUMERATE_USERNAME, RESOLVE_SOCIAL, \
RESOLVE_EMAIL, RESOLVE_BREACH, RESOLVE_DOMAIN, RESOLVE_PHONE, RESOLVE_WALLET, \
CORRELATE_IDENTITIES, FINISH_INVESTIGATION.
    • Each tool has a name, description, and input_schema.
    • RESOLVER_TOOLS and ALL_TOOLS lists, TOOL_NAME_TO_RESOLVER mapping.

  orchestrator.py
    • run_scan() — main Modal function: initialises graph, TelemetryCollector, \
GraphState, planner prompt; runs the agent loop (up to 30 turns); drains \
in-flight resolvers; runs GPU post-processing; generates report; finalises \
telemetry.
    • InFlightPool — manages concurrent Modal resolver spawns: submit(), \
harvest(), has_pending(), cancel_all().
    • _gpu_postprocess() — GPU entity extraction over node metadata.
    • _breach_correlate() — correlates identities via shared breach pivots.
    • Agent loop logic: harvest → call planner → spawn resolvers → immediate \
harvest → analyst brief → feed back to planner.

  telemetry/evaluator.py
    • _SYSTEM_PROMPT — the rubric used to grade five categories.
    • _precompute_metrics() — deterministic metrics before LLM call.
    • evaluate_bundle() — main entry point.

  resolvers/username.py, resolvers/email.py, resolvers/domain.py,
  resolvers/breach.py, resolvers/social.py, resolvers/identity_correlator.py,
  resolvers/phone.py, resolvers/wallet.py, resolvers/username_enum.py
    • Each is a Modal function that accepts an entity and returns enriched data.

PROPOSAL RULES:

1. Only propose changes that address RECURRING patterns — issues appearing in \
multiple scans, not one-off anomalies.
2. Each proposal must target a SPECIFIC file and section (e.g. \
"PLANNER_SYSTEM_PROMPT, TIER 3 discipline section" or \
"RESOLVE_EMAIL tool description in agent/tools.py").
3. The proposed_change field must be diff-ready: describe the exact text to \
add, remove, or modify — not vague advice. Quote specific wording where \
possible.
4. Prioritise by impact:
   • priority=1: fixes a recurring issue in a weak category (avg score <=6) \
that appears in >50% of scans
   • priority=2: fixes a recurring issue in a weak category appearing in \
25-50% of scans
   • priority=3: improves a moderate-scoring category (avg 6-8)
   • priority=4: minor improvement or edge-case fix
   • priority=5: nice-to-have, low-frequency issue
5. Generate at most 10 proposals, sorted by priority (1 first).
6. Do NOT propose changes to telemetry/evaluator.py or telemetry/proposer.py \
unless the evaluation rubric itself is clearly wrong.
7. Do NOT invent problems not evidenced in the aggregated data.

OUTPUT FORMAT — respond with ONLY valid JSON, no markdown fences, no preamble:

[
  {
    "target_file": "<relative file path>",
    "section_description": "<specific section, constant, or function name>",
    "current_behavior": "<what the system currently does, 1-2 sentences>",
    "proposed_change": "<exact diff-ready description of the change>",
    "rationale": "<why, citing evidence: category scores, finding frequency, \
pct_scans>",
    "expected_impact": "<predicted improvement to which category score>",
    "priority": <int 1-5>
  },
  ...
]"""


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------


def _build_proposal_prompt(
    aggregation: dict[str, Any],
    scan_ids: list[str],
) -> str:
    """Format the aggregated scorecard data into a user message for the LLM."""
    sections: list[str] = []

    sections.append(
        f"---SCAN SAMPLE---\n"
        f"scan_count={aggregation['scan_count']} "
        f"average_overall_score={aggregation['average_overall_score']} "
        f"individual_scores={aggregation['overall_scores']}\n"
        f"scan_ids={scan_ids}"
    )

    sections.append(
        "---CATEGORY SUMMARY---\n"
        + json.dumps(aggregation["category_summary"], indent=2)
    )

    sections.append(
        "---WEAK CATEGORIES (avg score <= 6)---\n"
        + (", ".join(aggregation["weak_categories"]) or "(none)")
    )

    sections.append(
        "---CROSS-SCAN RECURRING FINDINGS (appear in >=50% of scans)---\n"
        + json.dumps(aggregation["cross_scan_findings"], indent=2)
    )

    sections.append(
        "---CROSS-SCAN RECURRING SUGGESTIONS---\n"
        + json.dumps(aggregation["cross_scan_suggestions"], indent=2)
    )

    sections.append(
        "---RESOLVER AGGREGATE STATS---\n"
        + json.dumps(aggregation["resolver_aggregate"], indent=2)
    )

    sections.append(
        "Analyse the patterns above and produce the improvement proposals JSON now."
    )

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# JSON extraction (reuse pattern from evaluator)
# ---------------------------------------------------------------------------


def _extract_json_array(text: str) -> list[dict[str, Any]]:
    """Extract a JSON array from the LLM response."""
    fenced = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
    if fenced:
        return json.loads(fenced.group(1))
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        return json.loads(text[start : end + 1])
    return json.loads(text)


# ---------------------------------------------------------------------------
# Cache key
# ---------------------------------------------------------------------------


def _cache_key(scan_ids: list[str]) -> str:
    """Stable cache key from a sorted list of scan IDs."""
    joined = ",".join(sorted(scan_ids))
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def generate_proposals(last_n: int = 10) -> dict[str, Any]:
    """Collect the *last_n* evaluation scorecards, aggregate cross-scan
    patterns, and use an LLM call to generate improvement proposals.

    Returns a dict matching the ``ProposalReport`` schema.

    Raises:
        ValueError: if fewer than ``_MIN_SCORECARDS`` scorecards are available.
    """
    import modal

    from anthropic import Anthropic

    scorecards = _collect_scorecards(last_n)

    if len(scorecards) < _MIN_SCORECARDS:
        raise ValueError(
            f"Need at least {_MIN_SCORECARDS} evaluated scans to generate proposals; "
            f"found {len(scorecards)}. Run more scans and evaluate them first."
        )

    scan_ids = [sc["scan_id"] for sc in scorecards]
    cache_key = _cache_key(scan_ids)

    # Check cache
    proposals_dict = modal.Dict.from_name(PROPOSALS_DICT_NAME, create_if_missing=True)
    try:
        cached = proposals_dict[cache_key]
        if isinstance(cached, dict) and "proposals" in cached:
            logger.info("Returning cached proposals for key %s", cache_key)
            return cached
    except KeyError:
        pass
    except Exception as exc:
        logger.warning("Cache read failed: %s", exc)

    aggregation = _aggregate_scorecards(scorecards)
    user_message = _build_proposal_prompt(aggregation, scan_ids)

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
        logger.exception("Proposal LLM call failed")
        raise

    try:
        raw_proposals = _extract_json_array(raw_text)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error(
            "Failed to parse proposals JSON: %s\nRaw: %s", exc, raw_text[:500]
        )
        raise ValueError(f"LLM returned invalid JSON: {exc}") from exc

    # Validate each proposal
    validated: list[dict[str, Any]] = []
    for item in raw_proposals:
        proposal = ImprovementProposal.model_validate(item)
        validated.append(proposal.model_dump())

    # Sort by priority ascending (1 = highest priority first)
    validated.sort(key=lambda p: p["priority"])

    report = ProposalReport(
        generated_at=time.time(),
        scan_ids=scan_ids,
        scan_count=len(scorecards),
        aggregate_overall_score=aggregation["average_overall_score"],
        proposals=validated,
    )
    result = report.model_dump()

    # Cache result
    try:
        proposals_dict[cache_key] = result
    except Exception as exc:
        logger.warning("Cache write failed: %s", exc)

    return result
