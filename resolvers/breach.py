"""Breach data resolver: Dehashed, LeakCheck, BreachDirectory."""

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

logger = logging.getLogger(__name__)

SOURCE = "breach_resolver"


def _entity_key(etype: str, value: str) -> str:
    v = value.strip().lower()
    return f"{etype}:{v}"


def _backoff(attempt: int) -> None:
    time.sleep(min(2**attempt, 60))


def _infer_entity_type(value: str) -> str:
    v = value.strip().lower()
    if "@" in v:
        return EntityType.EMAIL.value
    return EntityType.USERNAME.value


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=10)
def resolve_breach(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    q: modal.Queue,
    d: modal.Dict,
) -> None:
    """Search breach databases for an email or username."""
    if "stop" in d:
        return
    value = (entity_value or "").strip()
    if not value:
        return

    is_email = "@" in value
    node_id = _entity_key(entity_type, value)
    metadata: dict[str, Any] = {"value": value, "type": entity_type}
    edges_batch: list[dict[str, Any]] = [
        {"source": source_entity_key, "target": node_id, "relationship": "breach_lookup", "confidence": 1.0}
    ]
    to_push: list[dict[str, Any]] = []

    discovered_emails: set[str] = set()
    discovered_usernames: set[str] = set()

    def _process_result_entry(entry: dict) -> None:
        """Extract useful identifiers from a generic breach result entry."""
        for field in ("email", "username", "name"):
            val = (entry.get(field) or "").strip().lower()
            if not val:
                continue
            if field == "email" and "@" in val and val != value.lower():
                discovered_emails.add(val)
            elif field == "username" and val and val != value.lower():
                discovered_usernames.add(val)

    # 1. Dehashed — comprehensive breach search (paid)
    dehashed_email = os.environ.get("DEHASHED_EMAIL", "")
    dehashed_key = os.environ.get("DEHASHED_KEY", "")
    if dehashed_email and dehashed_key:
        try:
            query_field = "email" if is_email else "username"
            r = httpx.get(
                "https://api.dehashed.com/search",
                params={"query": f'{query_field}:"{value}"', "size": 100},
                auth=(dehashed_email, dehashed_key),
                headers={"Accept": "application/json"},
                timeout=20,
            )
            if r.status_code == 200:
                ddata = r.json()
                entries = ddata.get("entries") or []
                metadata["dehashed_total"] = ddata.get("total", 0)
                metadata["dehashed_entries"] = [
                    {
                        "email": e.get("email"),
                        "username": e.get("username"),
                        "database_name": e.get("database_name"),
                        "hashed_password": bool(e.get("hashed_password")),
                        "ip_address": e.get("ip_address"),
                        "name": e.get("name"),
                    }
                    for e in entries[:20]
                ]
                for entry in entries:
                    _process_result_entry(entry)
            elif r.status_code == 401:
                logger.warning("Dehashed auth failed (check DEHASHED_EMAIL/KEY)")
        except Exception as e:
            logger.warning("Dehashed failed for %s: %s", value, e)

    # 2. LeakCheck API
    leakcheck_key = os.environ.get("LEAKCHECK_KEY", "")
    if leakcheck_key:
        for attempt in range(3):
            try:
                r = httpx.get(
                    "https://leakcheck.io/api/v2/query/" + value,
                    headers={"X-API-Key": leakcheck_key},
                    timeout=15,
                )
                if r.status_code == 200:
                    lcdata = r.json()
                    sources = lcdata.get("sources", [])
                    metadata["leakcheck_found"] = lcdata.get("found", 0)
                    metadata["leakcheck_sources"] = [
                        {
                            "name": s.get("name"),
                            "date": s.get("date"),
                            "entries": s.get("entries"),
                        }
                        for s in sources[:20]
                    ]
                    for s in sources:
                        for entry in s.get("data", []):
                            if isinstance(entry, dict):
                                _process_result_entry(entry)
                elif r.status_code == 429:
                    _backoff(attempt)
                    continue
                break
            except Exception as e:
                logger.warning("LeakCheck attempt %s failed for %s: %s", attempt + 1, value, e)
                _backoff(attempt)

    # 3. BreachDirectory.org free API
    try:
        r = httpx.get(
            "https://breachdirectory.org/api",
            params={"func": "auto", "term": value},
            headers={
                "Authorization": f"Bearer {os.environ.get('BREACHDIRECTORY_KEY', '')}",
                "User-Agent": "osint-recon/1.0",
            },
            timeout=15,
        )
        if r.status_code == 200:
            bddata = r.json()
            results = bddata.get("result", [])
            metadata["breachdirectory_found"] = bddata.get("found", 0)
            metadata["breachdirectory_results"] = [
                {
                    "email": res.get("email"),
                    "has_password": bool(res.get("password") or res.get("sha1")),
                    "sources": res.get("sources", []),
                }
                for res in results[:20]
            ]
            for res in results:
                em = (res.get("email") or "").strip().lower()
                if em and "@" in em and em != value.lower():
                    discovered_emails.add(em)
    except Exception as e:
        logger.warning("BreachDirectory failed for %s: %s", value, e)

    # Push discovered entities
    for email in discovered_emails:
        ek = _entity_key(EntityType.EMAIL.value, email)
        to_push.append({
            "type": EntityType.EMAIL.value,
            "value": email,
            "source": SOURCE,
            "confidence": 0.8,
            "depth": depth + 1,
            "parent_key": node_id,
        })
        edges_batch.append({
            "source": node_id,
            "target": ek,
            "relationship": "breach_email",
            "confidence": 0.8,
        })

    for uname in list(discovered_usernames)[:10]:
        uk = _entity_key(EntityType.USERNAME.value, uname)
        to_push.append({
            "type": EntityType.USERNAME.value,
            "value": uname,
            "source": SOURCE,
            "confidence": 0.7,
            "depth": depth + 1,
            "parent_key": node_id,
        })
        edges_batch.append({
            "source": node_id,
            "target": uk,
            "relationship": "breach_username",
            "confidence": 0.7,
        })

    # Write node
    d[f"{NODE_PREFIX}{node_id}"] = {
        "id": node_id,
        "type": entity_type,
        "value": value,
        "metadata": metadata,
        "depth": depth,
    }

    d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch

    for item in to_push:
        q.put(item)
