"""Changelog system — records every applied change to prompts and orchestrator
logic in a Modal Dict (``osint-changelog``) and supports rollback.

Each entry captures:
  - timestamp and unique id
  - which proposal triggered the change
  - target file and section
  - full content before and after (enabling rollback)
  - evaluation scores before and after (for quality tracking)

Rollback returns the ``content_before`` text so the calling agent can apply
it and redeploy; this module does not hot-patch running code.

All Dict writes are best-effort: exceptions are swallowed so the changelog
never breaks a running agent loop.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)

CHANGELOG_DICT_NAME = "osint-changelog"

_ENTRIES_KEY = "entries"
_SNAPSHOT_PREFIX = "snapshot:"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ChangelogEntry(BaseModel):
    id: str
    timestamp: float
    proposal_id: str
    target_file: str
    section: str
    diff_summary: str
    content_before: str
    content_after: str
    evaluation_scores_before: dict[str, Any] | None = None
    evaluation_scores_after: dict[str, Any] | None = None
    rolled_back: bool = False
    rolled_back_at: float | None = None


class ChangelogResponse(BaseModel):
    entries: list[ChangelogEntry]
    total: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_dict():
    """Return the Modal Dict for the changelog (lazy import)."""
    import modal

    return modal.Dict.from_name(CHANGELOG_DICT_NAME, create_if_missing=True)


def _read_entries(d) -> list[dict[str, Any]]:
    """Read the full entries list from the Dict, returning [] on miss."""
    try:
        val = d[_ENTRIES_KEY]
        if isinstance(val, list):
            return val
    except KeyError:
        pass
    except Exception as exc:
        logger.warning("Failed to read changelog entries: %s", exc)
    return []


def _write_entries(d, entries: list[dict[str, Any]]) -> None:
    """Persist the entries list back to the Dict. Best-effort."""
    try:
        d[_ENTRIES_KEY] = entries
    except Exception as exc:
        logger.warning("Failed to write changelog entries: %s", exc)


def _snapshot_key(target_file: str, section: str) -> str:
    return f"{_SNAPSHOT_PREFIX}{target_file}:{section}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def record_change(
    proposal_id: str,
    target_file: str,
    section: str,
    diff_summary: str,
    content_before: str,
    content_after: str,
    evaluation_scores_before: dict[str, Any] | None = None,
    evaluation_scores_after: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record an applied change to the changelog.

    Saves a baseline snapshot for the ``(target_file, section)`` pair if one
    does not already exist (preserving the original state for full rollback).
    Appends the entry to the append-only entries list.

    Returns the new entry as a dict.
    """
    entry = ChangelogEntry(
        id=str(uuid.uuid4()),
        timestamp=time.time(),
        proposal_id=proposal_id,
        target_file=target_file,
        section=section,
        diff_summary=diff_summary,
        content_before=content_before,
        content_after=content_after,
        evaluation_scores_before=evaluation_scores_before,
        evaluation_scores_after=evaluation_scores_after,
    )
    entry_dict = entry.model_dump()

    try:
        d = _get_dict()

        # Preserve original baseline snapshot (only set once per target/section)
        snap_key = _snapshot_key(target_file, section)
        try:
            d[snap_key]  # already exists — don't overwrite
        except KeyError:
            try:
                d[snap_key] = content_before
            except Exception as exc:
                logger.warning("Failed to write baseline snapshot: %s", exc)

        # Append to entries log
        entries = _read_entries(d)
        entries.append(entry_dict)
        _write_entries(d, entries)

    except Exception as exc:
        logger.warning("record_change failed: %s", exc)

    return entry_dict


def get_changelog(
    limit: int = 50,
    target_file: str | None = None,
) -> list[dict[str, Any]]:
    """Return the most recent changelog entries, newest first.

    Args:
        limit: Maximum number of entries to return.
        target_file: If provided, filter to entries for this file only.
    """
    try:
        d = _get_dict()
        entries = _read_entries(d)
    except Exception as exc:
        logger.warning("get_changelog failed: %s", exc)
        return []

    if target_file:
        entries = [e for e in entries if e.get("target_file") == target_file]

    # Newest first
    entries.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
    return entries[:limit]


def rollback_change(entry_id: str) -> dict[str, Any]:
    """Mark a changelog entry as rolled back and return the restored content.

    The returned dict contains:
      - ``entry``: the updated changelog entry (with ``rolled_back=True``)
      - ``restored_content``: the ``content_before`` text to re-apply
      - ``target_file``: the file that should be updated
      - ``section``: the section within that file

    Raises:
        ValueError: if no entry with ``entry_id`` is found, or if the entry
                    was already rolled back.
    """
    d = _get_dict()
    entries = _read_entries(d)

    idx = next((i for i, e in enumerate(entries) if e.get("id") == entry_id), None)
    if idx is None:
        raise ValueError(f"No changelog entry found with id={entry_id!r}")

    entry = entries[idx]
    if entry.get("rolled_back"):
        raise ValueError(
            f"Entry {entry_id!r} was already rolled back at "
            f"{entry.get('rolled_back_at')}"
        )

    # Mark as rolled back
    entry["rolled_back"] = True
    entry["rolled_back_at"] = time.time()
    entries[idx] = entry
    _write_entries(d, entries)

    return {
        "entry": entry,
        "restored_content": entry["content_before"],
        "target_file": entry["target_file"],
        "section": entry["section"],
    }


def get_baseline_snapshot(target_file: str, section: str) -> str | None:
    """Return the original (pre-any-change) content for a target/section pair.

    Returns None if no baseline snapshot has been recorded yet.
    """
    try:
        d = _get_dict()
        snap_key = _snapshot_key(target_file, section)
        return d[snap_key]
    except KeyError:
        return None
    except Exception as exc:
        logger.warning("get_baseline_snapshot failed: %s", exc)
        return None
