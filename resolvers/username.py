"""Username resolver: GitHub API (Phase 1). Other sources (Gravatar, Keybase, Reddit) in Phase 2."""

import logging
import os
import time
import uuid
from typing import Any

import modal
import requests

# Import app so this module can register the Modal function; avoid circular import by
# not importing orchestrator here.
from app import app, image, osint_secret

from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType
from resolvers._domain_blocklist import BLOCKED_DOMAINS
from scan_log import log_scan_event
from stream import write_stream_event

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
SOURCE = "github"


def _entity_key(etype: str, value: str) -> str:
    v = (str(value) if not isinstance(value, str) else value).strip().lower()
    return f"{etype}:{v}"


def _backoff(attempt: int, retry_after: int | None = None) -> None:
    if retry_after and retry_after > 0:
        time.sleep(min(retry_after, 60))
    else:
        time.sleep(min(2**attempt, 60))


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=10)
def resolve_github(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    scan_id: str = "",
) -> None:
    """
    Resolve a username via GitHub API. Write node and edges to d, push discovered
    entities to q. Fails gracefully (log and return) on errors.
    """
    if not scan_id:
        return
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
    if "stop" in d:
        return
    username = (entity_value or "").strip()
    if not username:
        return
    token = os.environ.get("GITHUB_TOKEN")
    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{GITHUB_API}/users/{requests.utils.quote(username, safe='')}"
    last_error: Exception | None = None
    last_response_preview: str = ""
    for attempt in range(4):
        try:
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code == 404:
                return
            if r.status_code == 403:
                retry_after = r.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    _backoff(attempt, int(retry_after))
                else:
                    _backoff(attempt)
                continue
            if r.status_code == 429:
                _backoff(attempt, 60)
                continue
            r.raise_for_status()
            data = r.json()
            break
        except requests.RequestException as e:
            last_error = e
            last_response_preview = (getattr(getattr(e, "response", None), "text", None) or "")[:500]
            logger.warning("GitHub request attempt %s failed: %s", attempt + 1, e)
            _backoff(attempt)
    else:
        if last_error:
            logger.exception("GitHub resolver failed for %s: %s", username, last_error)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_github",
                entity_key=_entity_key(EntityType.USERNAME.value, username),
                error=str(last_error),
                service="GitHub API",
                response_preview=last_response_preview,
            )
        return

    # Build node for this user
    node_id = _entity_key(EntityType.USERNAME.value, username)
    node_key = f"{NODE_PREFIX}{node_id}"
    node_payload: dict[str, Any] = {
        "id": node_id,
        "type": EntityType.USERNAME.value,
        "value": username,
        "metadata": {
            "login": data.get("login"),
            "name": data.get("name"),
            "company": data.get("company"),
            "blog": data.get("blog"),
            "location": data.get("location"),
            "email": data.get("email"),
            "bio": data.get("bio"),
            "public_repos": data.get("public_repos"),
            "followers": data.get("followers"),
            "html_url": data.get("html_url"),
        },
        "depth": depth,
    }
    d[node_key] = node_payload
    write_stream_event(scan_id, "node", node_payload)

    # Edge from source to this node
    edges_batch: list[dict[str, Any]] = [
        {"source": source_entity_key, "target": node_id, "relationship": "resolved_by_github", "confidence": 1.0}
    ]

    # Discovered entities to push to queue (depth + 1)
    to_push: list[dict[str, Any]] = []

    # Email if public
    email = (data.get("email") or "").strip()
    if email and "@" in email:
        ek = _entity_key(EntityType.EMAIL.value, email)
        to_push.append(
            {
                "type": EntityType.EMAIL.value,
                "value": email,
                "source": SOURCE,
                "confidence": 0.9,
                "depth": depth + 1,
                "parent_key": node_id,
            }
        )
        edges_batch.append({"source": node_id, "target": ek, "relationship": "has_email", "confidence": 0.9})

    # Blog/domain if present
    blog = (data.get("blog") or "").strip()
    if blog:
        if not blog.startswith("http"):
            blog = "https://" + blog
        try:
            from urllib.parse import urlparse
            domain = urlparse(blog).netloc
            if domain and "." in domain and domain.lower() in BLOCKED_DOMAINS:
                log_scan_event(scan_id, "entity_skipped", reason="blocklist", entity_key=_entity_key(EntityType.DOMAIN.value, domain))
            elif domain and "." in domain:
                dk = _entity_key(EntityType.DOMAIN.value, domain)
                to_push.append(
                    {
                        "type": EntityType.DOMAIN.value,
                        "value": domain,
                        "source": SOURCE,
                        "confidence": 0.8,
                        "depth": depth + 1,
                        "parent_key": node_id,
                    }
                )
                edges_batch.append({"source": node_id, "target": dk, "relationship": "has_blog_domain", "confidence": 0.8})
        except Exception as e:
            logger.warning("Blog domain parse failed for %s (blog=%s): %s", username, blog[:50], e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_github",
                entity_key=node_id,
                error=str(e),
                service="blog_domain_parse",
            )

    batch_key = f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"
    d[batch_key] = edges_batch
    for edge in edges_batch:
        write_stream_event(scan_id, "edge", edge)

