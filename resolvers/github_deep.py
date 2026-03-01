"""Exhaustive GitHub intelligence extractor.

Architecture (two-tier parallel):
  1. resolve_github_deep — orchestrator; fetches all repos, starred repos,
     followers/following, orgs, gists; spawns _fetch_repo_intel per repo in
     parallel; collects results in batches and calls _summarize_repo_batch
     (fresh Claude instance per batch) to compress raw findings.
  2. _fetch_repo_intel — Modal sub-function; fetches ALL commit pages for one
     repo, contributors, and README snippet; returns compact RepoIntel dict.
  3. _summarize_repo_batch — Modal sub-function; receives ≤20 RepoIntel dicts,
     calls its own Anthropic client (fresh context), returns BatchSummary.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import httpx
import modal

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType
from scan_log import log_scan_event
from stream import write_stream_event

logger = logging.getLogger(__name__)

SOURCE = "github_deep"
GITHUB_API = "https://api.github.com"

# Summarizer batch size — how many RepoIntel dicts per Claude call
_BATCH_SIZE = 20
# Max chars of serialised batch sent to the summariser Claude
_BATCH_CHAR_LIMIT = 8_000
# README truncation before sending to summariser
_README_MAX_CHARS = 2_000
# Rate-limit headroom: pause when fewer than this many requests remain
_RATE_LIMIT_HEADROOM = 100
# Summariser model — lightweight is fine for extraction
_SUMMARISER_MODEL = "claude-haiku-4-5-20251001"

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _entity_key(etype: str, value: str) -> str:
    v = (str(value) if not isinstance(value, str) else value).strip().lower()
    return f"{etype}:{v}"


def _make_headers(token: str) -> dict[str, str]:
    h: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _check_rate_limit(response: httpx.Response, token: str) -> None:
    """Sleep until rate limit resets if we're running low."""
    remaining = int(response.headers.get("X-RateLimit-Remaining", 9999))
    if remaining < _RATE_LIMIT_HEADROOM:
        reset_ts = int(response.headers.get("X-RateLimit-Reset", 0))
        now = int(time.time())
        wait = max(reset_ts - now + 2, 5)
        logger.info("Rate limit low (%d remaining), sleeping %ds", remaining, wait)
        time.sleep(min(wait, 120))


def _gh_get(
    url: str,
    headers: dict,
    params: dict | None = None,
    token: str = "",
) -> dict | list | None:
    """GET with exponential backoff on 403/429, rate-limit awareness."""
    for attempt in range(5):
        try:
            r = httpx.get(url, headers=headers, params=params, timeout=25)
            if r.status_code == 404:
                return None
            if r.status_code in (403, 429):
                retry_after = r.headers.get("Retry-After") or r.headers.get("X-RateLimit-Reset")
                delay: int
                if retry_after:
                    try:
                        reset_ts = int(retry_after)
                        delay = max(reset_ts - int(time.time()) + 2, 5)
                    except ValueError:
                        delay = min(2 ** attempt, 60)
                else:
                    delay = min(2 ** attempt, 60)
                time.sleep(min(delay, 120))
                continue
            r.raise_for_status()
            _check_rate_limit(r, token)
            return r.json()
        except httpx.HTTPStatusError as e:
            logger.warning("GitHub HTTP error attempt %d: %s", attempt + 1, e)
            time.sleep(min(2 ** attempt, 60))
        except Exception as e:
            logger.warning("GitHub request attempt %d failed: %s", attempt + 1, e)
            time.sleep(min(2 ** attempt, 60))
    return None


def _paginate(
    base_url: str,
    headers: dict,
    params: dict | None = None,
    max_pages: int = 0,
    token: str = "",
) -> list:
    """Collect all pages. max_pages=0 means no limit."""
    results: list = []
    p = dict(params or {})
    p.setdefault("per_page", "100")
    page = 1
    while True:
        if max_pages and page > max_pages:
            break
        p["page"] = str(page)
        data = _gh_get(base_url, headers, params=p, token=token)
        if not data or not isinstance(data, list):
            break
        results.extend(data)
        if len(data) < int(p["per_page"]):
            break
        page += 1
    return results


# ---------------------------------------------------------------------------
# Timezone inference
# ---------------------------------------------------------------------------

def _infer_timezone(timestamps: list[str]) -> dict[str, Any]:
    """Given ISO-8601 UTC commit timestamps, infer timezone offset and schedule."""
    if not timestamps:
        return {}

    hour_counts: Counter[int] = Counter()
    weekday_counts: Counter[int] = Counter()

    for ts in timestamps:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour_counts[dt.hour] += 1
            weekday_counts[dt.weekday()] += 1
        except Exception:
            continue

    if not hour_counts:
        return {}

    total = sum(hour_counts.values())
    peak_hour_utc = hour_counts.most_common(1)[0][0]

    # Assume peak activity is at 14:00 local time (2pm) — common for devs
    assumed_local_peak = 14
    tz_offset = (assumed_local_peak - peak_hour_utc + 12) % 24 - 12
    tz_label = f"UTC{tz_offset:+d}" if tz_offset != 0 else "UTC"

    weekend_commits = weekday_counts.get(5, 0) + weekday_counts.get(6, 0)
    weekend_ratio = round(weekend_commits / total, 3) if total else 0.0

    # Hour buckets: morning 6-12, afternoon 12-18, evening 18-24, night 0-6
    def _bucket_share(hours: range) -> float:
        return round(sum(hour_counts.get(h, 0) for h in hours) / total, 3) if total else 0.0

    return {
        "timezone_estimate": tz_label,
        "peak_hour_utc": peak_hour_utc,
        "weekend_ratio": weekend_ratio,
        "work_schedule": {
            "morning_share": _bucket_share(range(6, 12)),
            "afternoon_share": _bucket_share(range(12, 18)),
            "evening_share": _bucket_share(range(18, 24)),
            "night_share": _bucket_share(range(0, 6)),
        },
        "commit_sample_size": total,
    }


# ---------------------------------------------------------------------------
# Sub-function: fetch intel for a single repo
# ---------------------------------------------------------------------------

@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=20)
def _fetch_repo_intel(full_name: str, username: str, token: str) -> dict[str, Any]:
    """Fetch all commits, contributors, and README for one repo.

    Returns a compact RepoIntel dict — no raw API objects, only extracted fields.
    """
    headers = _make_headers(token)

    # All commit pages for this author
    commits = _paginate(
        f"{GITHUB_API}/repos/{full_name}/commits",
        headers,
        params={"author": username},
        token=token,
    )

    emails: list[str] = []
    timestamps: list[str] = []
    for commit in commits:
        commit_data = commit.get("commit", {})
        for role in ("author", "committer"):
            actor = commit_data.get(role, {}) or {}
            email = (actor.get("email") or "").strip().lower()
            if (
                email
                and "@" in email
                and "noreply" not in email
                and "github.com" not in email
                and "users.noreply" not in email
            ):
                emails.append(email)
            ts = actor.get("date", "")
            if ts:
                timestamps.append(ts)

    # Contributors (includes anonymous via anon=true)
    contributors_raw = _paginate(
        f"{GITHUB_API}/repos/{full_name}/contributors",
        headers,
        params={"anon": "true"},
        token=token,
    )
    contributors: list[str] = [
        c.get("login", "")
        for c in contributors_raw
        if c.get("login") and c.get("login") != username
    ]

    # README (best-effort, truncated)
    readme_snippet = ""
    readme_data = _gh_get(
        f"{GITHUB_API}/repos/{full_name}/readme",
        headers,
        token=token,
    )
    if readme_data and isinstance(readme_data, dict):
        encoded = readme_data.get("content", "")
        try:
            decoded = base64.b64decode(encoded.replace("\n", "")).decode("utf-8", errors="replace")
            readme_snippet = decoded[:_README_MAX_CHARS]
        except Exception:
            pass

    return {
        "full_name": full_name,
        "emails": list(set(emails)),
        "contributors": contributors,
        "timestamps": timestamps,
        "readme_snippet": readme_snippet,
    }


# ---------------------------------------------------------------------------
# Sub-function: summarise a batch of RepoIntel dicts via fresh Claude instance
# ---------------------------------------------------------------------------

_SUMMARISER_SYSTEM = """\
You are an OSINT data extractor. You receive a JSON array of GitHub repo intelligence objects for a single user.
Each object has: full_name, emails (list), contributors (list of usernames), timestamps (list of ISO dates), readme_snippet (string).

Extract and return ONLY a JSON object with these keys (no prose, no markdown fences):
{
  "emails": ["unique email addresses found across all repos"],
  "contributors": ["unique co-contributor GitHub usernames"],
  "readme_entities": {
    "emails": ["emails found in READMEs"],
    "domains": ["domains/URLs found in READMEs"],
    "usernames": ["social handles or usernames found in READMEs"],
    "names": ["real names mentioned in READMEs"]
  },
  "topics": ["inferred interest topics from repo names and README content"],
  "languages": ["programming languages mentioned"]
}

Rules:
- Deduplicate all lists.
- Exclude the target username from contributors.
- For readme_entities, extract only concrete identifiers (emails, domains, handles) — not generic words.
- Keep topics to ≤10 most specific items.
- Output ONLY valid JSON. No explanation."""


@app.function(image=image, secrets=[osint_secret])
def _summarize_repo_batch(repo_intel_list: list[dict], username: str) -> dict[str, Any]:
    """Call a fresh Claude instance to extract signals from a batch of RepoIntel dicts."""
    from anthropic import Anthropic

    client = Anthropic()

    # Serialize and truncate to stay within context budget
    raw = json.dumps(repo_intel_list, ensure_ascii=False)
    if len(raw) > _BATCH_CHAR_LIMIT:
        # Truncate each readme_snippet further to fit
        trimmed: list[dict] = []
        budget_per_item = _BATCH_CHAR_LIMIT // max(len(repo_intel_list), 1)
        for item in repo_intel_list:
            item = dict(item)
            item["readme_snippet"] = item.get("readme_snippet", "")[:300]
            trimmed.append(item)
        raw = json.dumps(trimmed, ensure_ascii=False)[:_BATCH_CHAR_LIMIT]

    try:
        message = client.messages.create(
            model=_SUMMARISER_MODEL,
            max_tokens=1024,
            system=_SUMMARISER_SYSTEM,
            messages=[{
                "role": "user",
                "content": f"Target username: {username}\n\nRepo intel batch:\n{raw}",
            }],
        )
        text = message.content[0].text.strip()
        # Strip markdown fences if model adds them
        if text.startswith("```"):
            text = re.sub(r"^```[a-z]*\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
        return json.loads(text)
    except Exception as e:
        logger.warning("Summariser Claude call failed: %s — falling back to local extraction", e)
        return _local_extract_batch(repo_intel_list, username)


def _local_extract_batch(repo_intel_list: list[dict], username: str) -> dict[str, Any]:
    """Deterministic fallback when the summariser LLM call fails."""
    emails: set[str] = set()
    contributors: set[str] = set()
    readme_emails: set[str] = set()
    readme_domains: set[str] = set()

    _email_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    _domain_re = re.compile(r"https?://([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})")

    for item in repo_intel_list:
        emails.update(item.get("emails", []))
        for c in item.get("contributors", []):
            if c and c != username:
                contributors.add(c)
        readme = item.get("readme_snippet", "")
        readme_emails.update(m.lower() for m in _email_re.findall(readme))
        readme_domains.update(m.lower() for m in _domain_re.findall(readme))

    return {
        "emails": list(emails),
        "contributors": list(contributors),
        "readme_entities": {
            "emails": list(readme_emails),
            "domains": list(readme_domains),
            "usernames": [],
            "names": [],
        },
        "topics": [],
        "languages": [],
    }


# ---------------------------------------------------------------------------
# Main resolver
# ---------------------------------------------------------------------------

@app.function(image=image, secrets=[osint_secret], timeout=600)
@modal.concurrent(max_inputs=5)
def resolve_github_deep(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    scan_id: str = "",
) -> None:
    """Exhaustive GitHub intelligence: all repos, all commit emails, collaborator
    networks, timezone inference, starred repo interests, README/bio parsing."""
    if not scan_id:
        return
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
    if "stop" in d:
        return
    username = (entity_value or "").strip()
    if not username:
        return

    token = os.environ.get("GITHUB_TOKEN", "")
    headers = _make_headers(token)

    node_id = _entity_key(EntityType.USERNAME.value, username)
    metadata: dict[str, Any] = {"username": username}
    edges_batch: list[dict[str, Any]] = [
        {
            "source": source_entity_key,
            "target": node_id,
            "relationship": "github_deep",
            "confidence": 1.0,
        }
    ]
    to_push: list[dict[str, Any]] = []

    # -----------------------------------------------------------------------
    # 1. Fetch ALL public repos (no cap)
    # -----------------------------------------------------------------------
    repos = _paginate(
        f"{GITHUB_API}/users/{username}/repos",
        headers,
        params={"type": "public", "sort": "updated"},
        token=token,
    )
    metadata["repo_count"] = len(repos)
    metadata["repos"] = [r.get("full_name") for r in repos]

    # -----------------------------------------------------------------------
    # 2. Spawn _fetch_repo_intel for every repo in parallel
    # -----------------------------------------------------------------------
    if "stop" not in d and repos:
        full_names = [r.get("full_name", "") for r in repos if r.get("full_name")]
        spawn_refs: list[Any] = []
        for fn in full_names:
            if "stop" in d:
                break
            ref = _fetch_repo_intel.spawn(fn, username, token)
            spawn_refs.append(ref)

        repo_intel_list: list[dict] = []
        for ref in spawn_refs:
            try:
                result = ref.get(timeout=120)
                if result:
                    repo_intel_list.append(result)
            except Exception as e:
                logger.warning("_fetch_repo_intel failed: %s", e)

        # -----------------------------------------------------------------------
        # 3. Collect all timestamps for timezone inference (done locally — no LLM)
        # -----------------------------------------------------------------------
        all_timestamps: list[str] = []
        for item in repo_intel_list:
            all_timestamps.extend(item.get("timestamps", []))
        tz_info = _infer_timezone(all_timestamps)
        metadata.update(tz_info)

        # -----------------------------------------------------------------------
        # 4. Summarise repo batches via fresh Claude instances
        # -----------------------------------------------------------------------
        all_emails: set[str] = set()
        all_contributors: set[str] = set()
        all_topics: list[str] = []
        all_languages: list[str] = []
        readme_emails: set[str] = set()
        readme_domains: set[str] = set()
        readme_usernames: set[str] = set()
        readme_names: list[str] = []

        batch_refs: list[Any] = []
        for i in range(0, len(repo_intel_list), _BATCH_SIZE):
            if "stop" in d:
                break
            batch = repo_intel_list[i: i + _BATCH_SIZE]
            ref = _summarize_repo_batch.spawn(batch, username)
            batch_refs.append(ref)

        for ref in batch_refs:
            try:
                summary = ref.get(timeout=90)
                if not summary:
                    continue
                all_emails.update(summary.get("emails", []))
                all_contributors.update(summary.get("contributors", []))
                all_topics.extend(summary.get("topics", []))
                all_languages.extend(summary.get("languages", []))
                re_ents = summary.get("readme_entities", {})
                readme_emails.update(re_ents.get("emails", []))
                readme_domains.update(re_ents.get("domains", []))
                readme_usernames.update(re_ents.get("usernames", []))
                readme_names.extend(re_ents.get("names", []))
            except Exception as e:
                logger.warning("_summarize_repo_batch failed: %s", e)

        metadata["commit_emails_found"] = len(all_emails)
        metadata["collaborators_found"] = len(all_contributors)
        metadata["readme_topics"] = list(dict.fromkeys(all_topics))[:10]
        metadata["readme_languages"] = list(dict.fromkeys(all_languages))[:10]
        if readme_names:
            metadata["readme_names"] = list(dict.fromkeys(readme_names))[:5]

        # Emit email nodes
        for email in all_emails:
            if "@" not in email:
                continue
            ek = _entity_key(EntityType.EMAIL.value, email)
            to_push.append({
                "type": EntityType.EMAIL.value,
                "value": email,
                "source": SOURCE,
                "confidence": 0.95,
                "depth": depth + 1,
                "parent_key": node_id,
            })
            edges_batch.append({
                "source": node_id,
                "target": ek,
                "relationship": "commit_email",
                "confidence": 0.95,
            })

        # Emit README email nodes
        for email in readme_emails - all_emails:
            if "@" not in email or "noreply" in email:
                continue
            ek = _entity_key(EntityType.EMAIL.value, email)
            to_push.append({
                "type": EntityType.EMAIL.value,
                "value": email,
                "source": SOURCE,
                "confidence": 0.75,
                "depth": depth + 1,
                "parent_key": node_id,
            })
            edges_batch.append({
                "source": node_id,
                "target": ek,
                "relationship": "readme_email",
                "confidence": 0.75,
            })

        # Emit README domain nodes
        _skip_domains = {"github.com", "githubusercontent.com", "shields.io", "travis-ci.org"}
        for domain in readme_domains:
            domain = domain.lower().strip()
            if not domain or domain in _skip_domains or len(domain) <= 4:
                continue
            ek = _entity_key(EntityType.DOMAIN.value, domain)
            to_push.append({
                "type": EntityType.DOMAIN.value,
                "value": domain,
                "source": SOURCE,
                "confidence": 0.7,
                "depth": depth + 1,
                "parent_key": node_id,
            })
            edges_batch.append({
                "source": node_id,
                "target": ek,
                "relationship": "readme_domain",
                "confidence": 0.7,
            })

        # Emit collaborator username nodes
        for collab in all_contributors:
            if not collab or collab == username:
                continue
            ck = _entity_key(EntityType.USERNAME.value, collab)
            to_push.append({
                "type": EntityType.USERNAME.value,
                "value": collab,
                "source": SOURCE,
                "confidence": 0.8,
                "depth": depth + 1,
                "parent_key": node_id,
            })
            edges_batch.append({
                "source": node_id,
                "target": ck,
                "relationship": "github_collaborator",
                "confidence": 0.8,
            })

        # Emit README username nodes
        for handle in readme_usernames:
            if not handle or handle == username:
                continue
            hk = _entity_key(EntityType.USERNAME.value, handle)
            to_push.append({
                "type": EntityType.USERNAME.value,
                "value": handle,
                "source": SOURCE,
                "confidence": 0.65,
                "depth": depth + 1,
                "parent_key": node_id,
            })
            edges_batch.append({
                "source": node_id,
                "target": hk,
                "relationship": "readme_mention",
                "confidence": 0.65,
            })

    # -----------------------------------------------------------------------
    # 5. Gists
    # -----------------------------------------------------------------------
    if "stop" not in d:
        gists = _paginate(f"{GITHUB_API}/users/{username}/gists", headers, token=token)
        metadata["gists"] = [g.get("html_url") for g in gists]
        metadata["gist_count"] = len(gists)

    # -----------------------------------------------------------------------
    # 6. Organizations
    # -----------------------------------------------------------------------
    if "stop" not in d:
        orgs_data = _paginate(f"{GITHUB_API}/users/{username}/orgs", headers, token=token)
        org_names = [o.get("login") for o in orgs_data if o.get("login")]
        metadata["organizations"] = org_names
        for org in org_names:
            ok = _entity_key(EntityType.USERNAME.value, org)
            to_push.append({
                "type": EntityType.USERNAME.value,
                "value": org,
                "source": SOURCE,
                "confidence": 0.8,
                "depth": depth + 1,
                "parent_key": node_id,
            })
            edges_batch.append({
                "source": node_id,
                "target": ok,
                "relationship": "github_org_member",
                "confidence": 0.8,
            })

    # -----------------------------------------------------------------------
    # 7. Followers and Following (all pages)
    # -----------------------------------------------------------------------
    if "stop" not in d:
        followers = _paginate(f"{GITHUB_API}/users/{username}/followers", headers, token=token)
        following = _paginate(f"{GITHUB_API}/users/{username}/following", headers, token=token)
        follower_logins = [f.get("login") for f in followers if f.get("login")]
        following_logins = [f.get("login") for f in following if f.get("login")]
        metadata["follower_count"] = len(follower_logins)
        metadata["following_count"] = len(following_logins)
        metadata["followers_sample"] = follower_logins[:20]
        metadata["following_sample"] = following_logins[:20]

    # -----------------------------------------------------------------------
    # 8. Starred repos — extract interests and affiliations
    # -----------------------------------------------------------------------
    if "stop" not in d:
        starred = _paginate(
            f"{GITHUB_API}/users/{username}/starred",
            headers,
            params={"sort": "created", "direction": "desc"},
            token=token,
        )
        starred_topics: list[str] = []
        starred_languages: list[str] = []
        starred_orgs: list[str] = []
        for repo in starred:
            lang = repo.get("language")
            if lang:
                starred_languages.append(lang)
            for topic in repo.get("topics", []):
                starred_topics.append(topic)
            owner = (repo.get("owner") or {}).get("login", "")
            owner_type = (repo.get("owner") or {}).get("type", "")
            if owner_type == "Organization" and owner:
                starred_orgs.append(owner)

        # Deduplicate and keep top-N by frequency
        def _top(lst: list[str], n: int = 15) -> list[str]:
            return [item for item, _ in Counter(lst).most_common(n)]

        metadata["starred_count"] = len(starred)
        metadata["starred_topics"] = _top(starred_topics)
        metadata["starred_languages"] = _top(starred_languages)
        metadata["starred_orgs"] = _top(starred_orgs, 10)

        # Emit starred org usernames as entities
        for org in set(starred_orgs):
            ok = _entity_key(EntityType.USERNAME.value, org)
            to_push.append({
                "type": EntityType.USERNAME.value,
                "value": org,
                "source": SOURCE,
                "confidence": 0.6,
                "depth": depth + 1,
                "parent_key": node_id,
            })
            edges_batch.append({
                "source": node_id,
                "target": ok,
                "relationship": "github_starred_org",
                "confidence": 0.6,
            })

    # -----------------------------------------------------------------------
    # 9. Write node to graph
    # -----------------------------------------------------------------------
    node_payload: dict[str, Any] = {
        "id": node_id,
        "type": EntityType.USERNAME.value,
        "value": username,
        "metadata": metadata,
        "depth": depth,
    }
    try:
        d[f"{NODE_PREFIX}{node_id}"] = node_payload
    except Exception as e:
        log_scan_event(
            scan_id,
            "resolver_failed",
            resolver="resolve_github_deep",
            entity_key=node_id,
            error=str(e),
            service="github_deep_dict_write",
            data_preview=str(node_payload)[:500],
        )
        return
    write_stream_event(scan_id, "node", node_payload)

    # -----------------------------------------------------------------------
    # 10. Write edges batch
    # -----------------------------------------------------------------------
    try:
        d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch
    except Exception as e:
        log_scan_event(
            scan_id,
            "resolver_failed",
            resolver="resolve_github_deep",
            entity_key=node_id,
            error=str(e),
            service="github_deep_dict_write",
            data_preview=str(edges_batch)[:500],
        )
        return
    for edge in edges_batch:
        write_stream_event(scan_id, "edge", edge)

    # -----------------------------------------------------------------------
    # 11. Write discovered child entities to graph dict (for orchestrator pickup)
    # -----------------------------------------------------------------------
    for entity in to_push:
        ek = _entity_key(entity["type"], entity["value"])
        child_node: dict[str, Any] = {
            "id": ek,
            "type": entity["type"],
            "value": entity["value"],
            "metadata": {
                "source": entity["source"],
                "confidence": entity["confidence"],
                "parent_key": entity.get("parent_key", node_id),
            },
            "depth": entity["depth"],
        }
        try:
            d[f"{NODE_PREFIX}{ek}"] = child_node
            write_stream_event(scan_id, "node", child_node)
        except Exception as e:
            logger.warning("Failed to write child entity %s: %s", ek, e)

    log_scan_event(
        scan_id,
        "resolver_completed",
        resolver="resolve_github_deep",
        entity_key=node_id,
        nodes_found=1 + len(to_push),
        edges_found=len(edges_batch),
    )
