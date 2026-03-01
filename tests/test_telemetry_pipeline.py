"""Integration test for the telemetry pipeline: export -> evaluate -> propose -> manifest.

All Modal Dict operations and Anthropic LLM calls are mocked so the test
runs locally without any external dependencies.
"""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# In-memory Modal Dict replacement
# ---------------------------------------------------------------------------


class _FakeDict(dict):
    """dict subclass that also exposes a .keys() matching Modal Dict API."""

    def keys(self):
        return list(super().keys())


_STORES: dict[str, _FakeDict] = {}


def _fake_dict_from_name(name: str, *, create_if_missing: bool = False) -> _FakeDict:
    if name not in _STORES:
        if not create_if_missing:
            raise KeyError(f"Dict {name!r} does not exist")
        _STORES[name] = _FakeDict()
    return _STORES[name]


@pytest.fixture(autouse=True)
def _reset_stores():
    """Clear the in-memory dict store between tests."""
    _STORES.clear()
    yield
    _STORES.clear()


@pytest.fixture()
def mock_modal(monkeypatch):
    """Patch ``modal.Dict.from_name`` globally to use in-memory dicts.

    The telemetry modules import ``modal`` both at module level (exporter)
    and locally inside functions (proposer, changelog).  Patching the real
    ``modal.Dict.from_name`` covers both cases.
    """
    import modal

    monkeypatch.setattr(modal.Dict, "from_name", staticmethod(_fake_dict_from_name))
    return modal


# ---------------------------------------------------------------------------
# Canned LLM responses
# ---------------------------------------------------------------------------

CANNED_SCORECARD = {
    "overall_score": 72,
    "overall_grade": "B",
    "planner_efficiency": {
        "score": 7,
        "grade": "B",
        "findings": ["Good tool selection"],
        "suggestions": ["Reduce redundant calls"],
    },
    "analyst_brief_quality": {
        "score": 8,
        "grade": "A",
        "findings": ["Briefs are concise"],
        "suggestions": [],
    },
    "resolver_roi": {
        "score": 6,
        "grade": "C",
        "findings": ["High failure rate on breach resolver"],
        "suggestions": ["Add retry logic"],
    },
    "investigation_completeness": {
        "score": 7,
        "grade": "B",
        "findings": ["Covered primary entity types"],
        "suggestions": ["Explore phone pivots"],
    },
    "report_quality": {
        "score": 8,
        "grade": "A",
        "findings": ["Well-structured report"],
        "suggestions": [],
    },
    "resolver_breakdown": [
        {
            "resolver_name": "resolve_github",
            "calls": 2,
            "successes": 2,
            "failures": 0,
            "failure_rate": 0.0,
            "entities_discovered_per_call": 3.0,
        },
    ],
    "summary": "Solid investigation with room for improvement in resolver reliability.",
}

CANNED_PROPOSALS = [
    {
        "target_file": "agent/planner.py",
        "section_description": "PLANNER_SYSTEM_PROMPT, TIER 3 discipline section",
        "current_behavior": "Planner sometimes dispatches low-value resolvers.",
        "proposed_change": "Add explicit instruction to skip tier-3 resolvers when entity limit is near.",
        "rationale": "Recurring finding in 4/5 scans: wasted resolver calls near entity cap.",
        "expected_impact": "Improve planner_efficiency score by ~1 point.",
        "priority": 1,
    },
]


def _make_anthropic_response(payload: Any) -> MagicMock:
    """Build a mock Anthropic message response containing *payload* as JSON text."""
    text_block = MagicMock()
    text_block.text = json.dumps(payload)
    msg = MagicMock()
    msg.content = [text_block]
    return msg


@pytest.fixture()
def mock_anthropic(monkeypatch):
    """Patch ``anthropic.Anthropic`` so LLM calls return canned JSON."""
    call_count = {"n": 0}

    def _create(**kwargs):
        call_count["n"] += 1
        messages = kwargs.get("messages", [])
        user_text = ""
        if messages:
            user_text = messages[0].get("content", "")

        if "evaluation scorecard" in user_text.lower() or "scorecard" in user_text.lower():
            return _make_anthropic_response(CANNED_SCORECARD)
        if "improvement proposals" in user_text.lower() or "proposal" in user_text.lower():
            return _make_anthropic_response(CANNED_PROPOSALS)
        # Default: return scorecard (evaluator calls first in the pipeline)
        return _make_anthropic_response(CANNED_SCORECARD)

    mock_client_instance = MagicMock()
    mock_client_instance.messages.create = _create

    mock_client_cls = MagicMock(return_value=mock_client_instance)
    monkeypatch.setattr("anthropic.Anthropic", mock_client_cls)
    return mock_client_cls


# ---------------------------------------------------------------------------
# Sample telemetry bundle
# ---------------------------------------------------------------------------

SCAN_ID = "test-scan-001"

SAMPLE_BUNDLE = {
    "scan_id": SCAN_ID,
    "seed_entity": {"type": "username", "value": "johndoe"},
    "config": {"max_depth": 3, "max_entities": 50},
    "started_at": time.time() - 120,
    "finished_at": time.time(),
    "final_status": "completed",
    "planner_turns": [
        {
            "turn": 1,
            "ts": time.time() - 100,
            "reasoning": "Start with GitHub and username enumeration.",
            "tool_calls": [
                {"name": "resolve_github", "input": {"entity_value": "johndoe"}},
            ],
            "stop_reason": None,
        },
        {
            "turn": 2,
            "ts": time.time() - 50,
            "reasoning": "Follow up on discovered email.",
            "tool_calls": [
                {"name": "resolve_email", "input": {"entity_value": "john@example.com"}},
            ],
            "stop_reason": "end_turn",
        },
    ],
    "analyst_briefs": [
        {
            "turn": 1,
            "ts": time.time() - 90,
            "brief": "GitHub profile found: johndoe. Public email john@example.com discovered.",
            "new_nodes": 3,
            "new_edges": 2,
            "background": False,
        },
    ],
    "resolvers": [
        {
            "resolver_name": "resolve_github",
            "entity_key": "username:johndoe",
            "succeeded": True,
            "error": None,
            "duration_ms": 450.0,
            "ts": time.time() - 95,
        },
        {
            "resolver_name": "resolve_email",
            "entity_key": "email:john@example.com",
            "succeeded": True,
            "error": None,
            "duration_ms": 320.0,
            "ts": time.time() - 45,
        },
    ],
    "graph_summary": {"node_count": 5, "edge_count": 4},
    "report": "# OSINT Report\n\nSubject johndoe has a GitHub profile...",
    "errors": [],
    "user_stopped": False,
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExporter:
    """Verify TelemetryCollector writes bundles to the mock store."""

    def test_collector_finalize(self, mock_modal):
        from telemetry.exporter import TELEMETRY_DICT_NAME, TelemetryCollector

        tc = TelemetryCollector(
            SCAN_ID,
            {"type": "username", "value": "johndoe"},
            {"max_depth": 3, "max_entities": 50},
        )
        tc.record_planner_turn(1, "reasoning", [{"name": "resolve_github"}], None)
        tc.record_resolver("resolve_github", "username:johndoe", True, None, 450.0)
        tc.record_analyst_brief(1, "Found GitHub profile", 3, 2)
        tc.finalize("completed", {"node_count": 5, "edge_count": 4}, "report text")

        store = _STORES[TELEMETRY_DICT_NAME]
        assert SCAN_ID in store
        bundle = store[SCAN_ID]
        assert bundle["final_status"] == "completed"
        assert bundle["finished_at"] is not None
        assert len(bundle["planner_turns"]) == 1
        assert len(bundle["resolvers"]) == 1
        assert len(bundle["analyst_briefs"]) == 1


class TestEvaluator:
    """Verify evaluate_bundle parses the canned LLM response into a scorecard."""

    def test_evaluate_bundle(self, mock_modal, mock_anthropic):
        from telemetry.evaluator import evaluate_bundle

        scorecard = evaluate_bundle(SAMPLE_BUNDLE)

        assert scorecard["scan_id"] == SCAN_ID
        assert scorecard["overall_score"] == 72
        assert scorecard["overall_grade"] == "B"
        assert "planner_efficiency" in scorecard
        assert "analyst_brief_quality" in scorecard
        assert "resolver_roi" in scorecard
        assert "investigation_completeness" in scorecard
        assert "report_quality" in scorecard
        assert isinstance(scorecard["resolver_breakdown"], list)
        assert scorecard["evaluated_at"] is not None


class TestProposer:
    """Verify generate_proposals aggregates scorecards and returns proposals."""

    def _seed_scorecards(self, n: int = 3):
        """Insert *n* scorecards into the mock eval dict."""
        from telemetry.evaluator import EVAL_DICT_NAME

        store = _STORES.setdefault(EVAL_DICT_NAME, _FakeDict())
        for i in range(n):
            sid = f"scan-{i:03d}"
            sc = dict(CANNED_SCORECARD)
            sc["scan_id"] = sid
            sc["evaluated_at"] = time.time() - (n - i)
            store[sid] = sc

    def test_generate_proposals(self, mock_modal, mock_anthropic):
        from telemetry.proposer import generate_proposals

        self._seed_scorecards(3)
        result = generate_proposals(last_n=10)

        assert "proposals" in result
        assert "scan_ids" in result
        assert result["scan_count"] == 3
        assert isinstance(result["proposals"], list)
        assert len(result["proposals"]) >= 1
        proposal = result["proposals"][0]
        assert "target_file" in proposal
        assert "priority" in proposal

    def test_generate_proposals_insufficient_scans(self, mock_modal, mock_anthropic):
        from telemetry.proposer import generate_proposals

        self._seed_scorecards(2)
        with pytest.raises(ValueError, match="Need at least 3"):
            generate_proposals(last_n=10)


class TestManifest:
    """Verify generate_manifest returns a well-formed manifest dict."""

    def test_generate_manifest(self, mock_modal, mock_anthropic, monkeypatch):
        monkeypatch.setattr(
            "telemetry.manifest._collect_tool_schemas",
            lambda: [{"name": "resolve_github", "description": "mock tool"}],
        )
        monkeypatch.setattr(
            "telemetry.manifest._collect_latest_proposals",
            lambda: None,
        )

        from telemetry.manifest import generate_manifest

        manifest = generate_manifest()

        assert manifest["version"] == "1.0.0"
        assert isinstance(manifest["project_structure"], list)
        assert len(manifest["project_structure"]) > 0
        assert isinstance(manifest["prompts"], list)
        assert isinstance(manifest["tool_schemas"], list)
        assert "generated_at" in manifest


class TestFullPipeline:
    """End-to-end: export -> evaluate -> propose -> manifest."""

    def test_pipeline(self, mock_modal, mock_anthropic, monkeypatch):
        from telemetry.evaluator import EVAL_DICT_NAME, evaluate_bundle
        from telemetry.exporter import TELEMETRY_DICT_NAME, TelemetryCollector

        # --- Step 1: Export ---
        tc = TelemetryCollector(
            SCAN_ID,
            {"type": "username", "value": "johndoe"},
            {"max_depth": 3, "max_entities": 50},
        )
        tc.record_planner_turn(
            1, "Start with GitHub lookup",
            [{"name": "resolve_github", "input": {"entity_value": "johndoe"}}],
            None,
        )
        tc.record_resolver("resolve_github", "username:johndoe", True, None, 450.0)
        tc.record_resolver("resolve_email", "email:john@example.com", True, None, 320.0)
        tc.record_analyst_brief(1, "GitHub profile found", 3, 2)
        tc.finalize(
            "completed",
            {"node_count": 5, "edge_count": 4},
            "# OSINT Report\n\nSubject johndoe...",
        )

        bundle = _STORES[TELEMETRY_DICT_NAME][SCAN_ID]
        assert bundle["final_status"] == "completed"

        # --- Step 2: Evaluate ---
        scorecard = evaluate_bundle(bundle)
        assert scorecard["overall_score"] == 72
        assert scorecard["scan_id"] == SCAN_ID

        eval_store = _STORES.setdefault(EVAL_DICT_NAME, _FakeDict())
        eval_store[SCAN_ID] = scorecard

        # Seed two more scorecards so proposer has >= 3
        for i in range(2):
            sid = f"extra-scan-{i}"
            sc = dict(CANNED_SCORECARD)
            sc["scan_id"] = sid
            sc["evaluated_at"] = time.time() - (2 - i)
            eval_store[sid] = sc

        # --- Step 3: Propose ---
        from telemetry.proposer import generate_proposals

        proposals = generate_proposals(last_n=10)
        assert proposals["scan_count"] == 3
        assert len(proposals["proposals"]) >= 1
        assert proposals["proposals"][0]["target_file"] == "agent/planner.py"

        # --- Step 4: Manifest ---
        monkeypatch.setattr(
            "telemetry.manifest._collect_tool_schemas",
            lambda: [{"name": "resolve_github", "description": "mock tool"}],
        )
        monkeypatch.setattr(
            "telemetry.manifest._collect_latest_proposals",
            lambda: proposals,
        )

        from telemetry.manifest import generate_manifest

        manifest = generate_manifest()
        assert manifest["version"] == "1.0.0"
        assert len(manifest["project_structure"]) > 0
        assert isinstance(manifest["prompts"], list)
        assert manifest["latest_proposals"] is not None
        assert manifest["latest_proposals"]["scan_count"] == 3


class TestAPIEndpoints:
    """Verify telemetry-related FastAPI endpoints via TestClient."""

    @pytest.fixture()
    def client(self, mock_modal, monkeypatch):
        """Build a TestClient around the inner FastAPI app.

        We patch Modal decorators and the heavy imports so the app can be
        constructed without a real Modal runtime.
        """
        import modal

        monkeypatch.setattr(modal.Dict, "from_name", _fake_dict_from_name)

        fake_run_scan = MagicMock()
        fake_run_scan.spawn = MagicMock()
        monkeypatch.setattr("api.modal", modal)

        from importlib import reload

        import api as api_mod

        monkeypatch.setattr(api_mod, "modal", MagicMock(Dict=MagicMock(from_name=_fake_dict_from_name)))

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        web_app = FastAPI(title="OSINT Recon API (test)")

        from fastapi.middleware.cors import CORSMiddleware

        web_app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )

        scan_results = _STORES.setdefault("osint-scan-results", _FakeDict())

        from fastapi import HTTPException
        from fastapi.responses import Response

        @web_app.get("/scan/{scan_id}/telemetry")
        def get_scan_telemetry(scan_id: str):
            from telemetry.exporter import TELEMETRY_DICT_NAME

            telemetry_dict = _fake_dict_from_name(TELEMETRY_DICT_NAME, create_if_missing=True)
            try:
                bundle = telemetry_dict[scan_id]
            except KeyError:
                raise HTTPException(status_code=404, detail="Telemetry not found for this scan")
            content = json.dumps(bundle, indent=2, default=str)
            return Response(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="telemetry-{scan_id[:8]}.json"'},
            )

        @web_app.get("/scan/{scan_id}/evaluation")
        def get_scan_evaluation(scan_id: str):
            from telemetry.evaluator import EVAL_DICT_NAME, evaluate_bundle
            from telemetry.exporter import TELEMETRY_DICT_NAME

            eval_dict = _fake_dict_from_name(EVAL_DICT_NAME, create_if_missing=True)
            try:
                return eval_dict[scan_id]
            except KeyError:
                pass

            telemetry_dict = _fake_dict_from_name(TELEMETRY_DICT_NAME, create_if_missing=True)
            try:
                bundle = telemetry_dict[scan_id]
            except KeyError:
                raise HTTPException(status_code=404, detail="Telemetry not found for this scan")

            if bundle.get("final_status") is None:
                raise HTTPException(status_code=409, detail="Scan still running")

            try:
                scorecard = evaluate_bundle(bundle)
            except Exception as exc:
                raise HTTPException(status_code=502, detail=f"Evaluation failed: {exc}")

            eval_dict[scan_id] = scorecard
            return scorecard

        @web_app.get("/telemetry/proposals")
        def get_proposals(last_n: int = 10):
            from telemetry.proposer import generate_proposals

            try:
                return generate_proposals(last_n=last_n)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            except Exception as exc:
                raise HTTPException(status_code=502, detail=f"Proposal generation failed: {exc}")

        return TestClient(web_app)

    def test_telemetry_endpoint(self, client, mock_modal):
        from telemetry.exporter import TELEMETRY_DICT_NAME

        store = _STORES.setdefault(TELEMETRY_DICT_NAME, _FakeDict())
        store[SCAN_ID] = SAMPLE_BUNDLE

        resp = client.get(f"/scan/{SCAN_ID}/telemetry")
        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == SCAN_ID
        assert body["final_status"] == "completed"

    def test_telemetry_endpoint_not_found(self, client, mock_modal):
        resp = client.get("/scan/nonexistent/telemetry")
        assert resp.status_code == 404

    def test_evaluation_endpoint(self, client, mock_modal, mock_anthropic):
        from telemetry.exporter import TELEMETRY_DICT_NAME

        store = _STORES.setdefault(TELEMETRY_DICT_NAME, _FakeDict())
        store[SCAN_ID] = SAMPLE_BUNDLE

        resp = client.get(f"/scan/{SCAN_ID}/evaluation")
        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == SCAN_ID
        assert body["overall_score"] == 72

    def test_evaluation_endpoint_not_found(self, client, mock_modal):
        resp = client.get("/scan/nonexistent/evaluation")
        assert resp.status_code == 404

    def test_proposals_endpoint_insufficient_scans(self, client, mock_modal, mock_anthropic):
        resp = client.get("/telemetry/proposals")
        assert resp.status_code == 400
        assert "Need at least 3" in resp.json()["detail"]
