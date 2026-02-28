"""Deep GitHub resolver: repos, commit emails, gists, orgs, followers."""

import logging
import os
import time
import uuid
from typing import Any

import httpx
import modal

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType
from stream import write_stream_event

logger = logging.getLogger(__name__)

SOURCE = "github_deep"
GITHUB_API = "https://api.github.com"

# How many repos/gists/followers to process per user (avoid runaway API usage)
_MAX_REPOS = 30
_MAX_COMMITS_PER_REPO = 3  # pages of 100 commits each
_MAX_GISTS = 10
_MAX_FOLLOWERS = 50


def _entity_key(etype: str, value: str) -> str:
    v = value.strip().lower()
    return f"{etype}:{v}"


def _backoff(attempt: int, retry_after: int | None = None) -> None:
    delay = int(retry_after) if retry_after else min(2**attempt, 60)
    time.sleep(min(delay, 120))


def _gh_get(url: str, headers: dict, params: dict | None = None) -> dict | list | None:
    """GET with exponential backoff on 403/429."""
    for attempt in range(4):
        try:
            r = httpx.get(url, headers=headers, params=params, timeout=20)
            if r.status_code == 404:
                return None
            if r.status_code in (403, 429):
                retry_after = r.headers.get("Retry-After") or r.headers.get("X-RateLimit-Reset")
                _backoff(attempt, retry_after)
                continue
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            logger.warning("GitHub HTTP error attempt %s: %s", attempt + 1, e)
            _backoff(attempt)
        except Exception as e:
            logger.warning("GitHub request attempt %s failed: %s", attempt + 1, e)
            _backoff(attempt)
    return None


def _paginate(
    base_url: str,
    headers: dict,
    params: dict | None = None,
    max_pages: int = 5,
) -> list:
    """Collect all pages up to max_pages."""
    results = []
    p = dict(params or {})
    p.setdefault("per_page", "100")
    page = 1
    while page <= max_pages:
        p["page"] = str(page)
        data = _gh_get(base_url, headers, params=p)
        if not data or not isinstance(data, list):
            break
        results.extend(data)
        if len(data) < int(p["per_page"]):
            break
        page += 1
    return results


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=5)
def resolve_github_deep(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    q: modal.Queue,
    d: modal.Dict,
    scan_id: str = "",
) -> None:
    """Deep GitHub: extract commit emails, gists, orgs, and followers for a username."""
    if "stop" in d:
        return
    username = (entity_value or "").strip()
    if not username:
        return

    token = os.environ.get("GITHUB_TOKEN", "")
    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    node_id = _entity_key(EntityType.USERNAME.value, username)
    metadata: dict[str, Any] = {"username": username}
    edges_batch: list[dict[str, Any]] = [
        {"source": source_entity_key, "target": node_id, "relationship": "github_deep", "confidence": 1.0}
    ]
    to_push: list[dict[str, Any]] = []
    discovered_emails: set[str] = set()

    # 1. Fetch public repos
    repos = _paginate(
        f"{GITHUB_API}/users/{username}/repos",
        headers,
        params={"type": "public", "sort": "updated"},
        max_pages=(_MAX_REPOS // 100) + 1,
    )[:_MAX_REPOS]
    metadata["repo_count"] = len(repos)
    metadata["repos"] = [r.get("full_name") for r in repos]

    # 2. Fetch commit emails from each repo
    for repo in repos:
        if "stop" in d:
            break
        full_name = repo.get("full_name", "")
        if not full_name:
            continue
        try:
            commits = _paginate(
                f"{GITHUB_API}/repos/{full_name}/commits",
                headers,
                params={"author": username},
                max_pages=_MAX_COMMITS_PER_REPO,
            )
            for commit in commits:
                commit_data = commit.get("commit", {})
                for role in ("author", "committer"):
                    actor = commit_data.get(role, {})
                    email = (actor.get("email") or "").strip().lower()
                    name = (actor.get("name") or "").strip()
                    if (
                        email
                        and "@" in email
                        and "noreply" not in email
                        and "github.com" not in email
                    ):
                        discovered_emails.add(email)
        except Exception as e:
            logger.warning("Commit fetch failed for %s: %s", full_name, e)

    metadata["commit_emails_found"] = len(discovered_emails)

    # 3. Gists
    gists = _paginate(
        f"{GITHUB_API}/users/{username}/gists",
        headers,
        max_pages=1,
    )[:_MAX_GISTS]
    metadata["gists"] = [g.get("html_url") for g in gists]

    # 4. Organizations
    orgs_data = _paginate(f"{GITHUB_API}/users/{username}/orgs", headers, max_pages=1)
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

    # 5. Followers (top N — mutual connections can be valuable)
    followers = _paginate(f"{GITHUB_API}/users/{username}/followers", headers, max_pages=1)
    follower_logins = [f.get("login") for f in followers[:_MAX_FOLLOWERS] if f.get("login")]
    metadata["followers_sample"] = follower_logins[:20]

    # Push discovered emails as new entities
    for email in discovered_emails:
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

    # Write node
    node_payload = {
        "id": node_id,
        "type": EntityType.USERNAME.value,
        "value": username,
        "metadata": metadata,
        "depth": depth,
    }
    d[f"{NODE_PREFIX}{node_id}"] = node_payload
    write_stream_event(scan_id, "node", node_payload)

    d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch
    for edge in edges_batch:
        write_stream_event(scan_id, "edge", edge)

    for item in to_push:
        q.put(item)
