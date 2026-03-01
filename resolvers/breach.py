"""Breach data resolver: Dehashed, LeakCheck, BreachDirectory."""

import logging
import os
import time
import uuid
from typing import Any

import httpx
import modal
from leakcheck import LeakCheckAPI_Public, LeakCheckAPI_v2

from app import app, image, osint_secret
from resolvers._http import httpx_request
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType
from scan_log import log_scan_event
from stream import write_stream_event

logger = logging.getLogger(__name__)

SOURCE = "breach_resolver"


def _entity_key(etype: str, value: str) -> str:
    v = (str(value) if not isinstance(value, str) else value).strip().lower()
    return f"{etype}:{v}"


def _backoff(attempt: int) -> None:
    time.sleep(min(2**attempt, 60))


def _infer_entity_type(value: str) -> str:
    v = (str(value) if not isinstance(value, str) else value).strip().lower()
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
    scan_id: str = "",
) -> None:
    """Search breach databases for an email or username."""
    if not scan_id:
        return
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
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
        """Extract useful identifiers from a breach result entry.

        DeHashed v2 returns array-valued fields; LeakCheck/BreachDirectory
        may still return plain strings — handle both.
        """
        for field in ("email", "username", "name"):
            raw = entry.get(field)
            vals: list[str]
            if isinstance(raw, list):
                vals = [v for v in raw if isinstance(v, str)]
            elif isinstance(raw, str) and raw:
                vals = [raw]
            else:
                vals = []
            for val in vals:
                val = val.strip().lower()
                if not val:
                    continue
                if field == "email" and "@" in val and val != value.lower():
                    discovered_emails.add(val)
                elif field == "username" and val and val != value.lower():
                    discovered_usernames.add(val)

    # 1. Dehashed — comprehensive breach search (paid, v2 API)
    dehashed_key = os.environ.get("DEHASHED_KEY", "")
    if dehashed_key:
        try:
            query_field = "email" if is_email else "username"
            escaped_value = value.replace('"', '\\"')
            r = httpx.post(
                "https://api.dehashed.com/v2/search",
                json={
                    "query": f'{query_field}:"{escaped_value}"',
                    "page": 1,
                    "size": 100,
                    "de_dupe": True,
                },
                headers={
                    "DeHashed-Api-Key": dehashed_key,
                    "Content-Type": "application/json",
                },
                timeout=20,
            )
            if r.status_code == 200:
                ddata = r.json()
                entries = ddata.get("entries") or []
                logger.debug("Dehashed balance: %s", ddata.get("balance"))
                metadata["dehashed_total"] = ddata.get("total", 0)
                metadata["dehashed_balance"] = ddata.get("balance")
                metadata["dehashed_entries"] = [
                    {
                        "email": (e.get("email") or [None])[0],
                        "username": (e.get("username") or [None])[0],
                        "database_name": e.get("database_name"),
                        "hashed_password": (e.get("hashed_password") or [None])[0],
                        "ip_address": (e.get("ip_address") or [None])[0],
                        "phone": (e.get("phone") or [None])[0],
                        "name": (e.get("name") or [None])[0],
                    }
                    for e in entries[:20]
                ]
                for entry in entries:
                    _process_result_entry(entry)
            elif r.status_code == 401:
                logger.warning("Dehashed auth failed (check DEHASHED_KEY)")
                log_scan_event(
                    scan_id,
                    "resolver_failed",
                    resolver="resolve_breach",
                    entity_key=node_id,
                    error="Dehashed auth failed (401)",
                    service="Dehashed",
                    response_preview=(r.text or "")[:500],
                )
            elif r.status_code == 429:
                logger.warning("Dehashed rate limited for %s", value)
                log_scan_event(
                    scan_id,
                    "resolver_failed",
                    resolver="resolve_breach",
                    entity_key=node_id,
                    error="Dehashed rate limited (429)",
                    service="Dehashed",
                    response_preview=(r.text or "")[:500],
                )
            else:
                response_preview = (r.text or "")[:500]
                log_scan_event(
                    scan_id,
                    "resolver_failed",
                    resolver="resolve_breach",
                    entity_key=node_id,
                    error=f"Dehashed status {r.status_code}",
                    service="Dehashed",
                    response_preview=response_preview,
                )
        except Exception as e:
            response_preview = (getattr(getattr(e, "response", None), "text", None) or "")[:500]
            logger.warning("Dehashed failed for %s: %s", value, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_breach",
                entity_key=node_id,
                error=str(e),
                service="Dehashed",
                response_preview=response_preview,
            )

    # 2. LeakCheck API — free Public API when no key; Pro API v2 when LEAKCHECK_APIKEY set
    leakcheck_key = os.environ.get("LEAKCHECK_APIKEY") or os.environ.get("LEAKCHECK_KEY", "")
    use_pro = bool(leakcheck_key and len(leakcheck_key) >= 40)
    for attempt in range(3):
        try:
            if use_pro:
                api = LeakCheckAPI_v2(api_key=leakcheck_key)
                # v2 lookup() returns result['result'] — a list of breach records.
                # Each record: {email, username, password, hashed, last_breach,
                #               sources: [{name, date}, ...]}
                records: list[dict] = api.lookup(
                    query=value,
                    query_type="email" if is_email else "username",
                    limit=100,
                ) or []
                metadata["leakcheck_found"] = len(records)
                seen_sources: dict[str, Any] = {}
                leakcheck_entries: list[dict[str, Any]] = []
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    for src in (rec.get("sources") or []):
                        if isinstance(src, dict) and src.get("name"):
                            seen_sources.setdefault(src["name"], src.get("date"))
                        elif isinstance(src, str):
                            seen_sources.setdefault(src, None)
                    _process_result_entry(rec)
                    raw_hash = rec.get("hashed") or None
                    if raw_hash or rec.get("email") or rec.get("username"):
                        leakcheck_entries.append({
                            "email": rec.get("email") or None,
                            "username": rec.get("username") or None,
                            "hashed_password": raw_hash,
                            "sources": [
                                s.get("name") if isinstance(s, dict) else s
                                for s in (rec.get("sources") or [])
                                if s
                            ],
                        })
                metadata["leakcheck_sources"] = [
                    {"name": k, "date": v} for k, v in list(seen_sources.items())[:20]
                ]
                if leakcheck_entries:
                    metadata["leakcheck_entries"] = leakcheck_entries[:20]
            else:
                api = LeakCheckAPI_Public()
                # Public lookup() returns full response: {success, found, sources: [strings]}
                raw = api.lookup(query=value) or {}
                lcdata = raw if isinstance(raw, dict) else {}
                raw_sources = lcdata.get("sources") or []
                metadata["leakcheck_found"] = lcdata.get("found", 0)
                metadata["leakcheck_sources"] = [
                    {"name": s} if isinstance(s, str) else s for s in raw_sources[:20]
                ]
                time.sleep(1)  # Public API 1 RPS
            break
        except ValueError as e:
            err = str(e).lower()
            if "429" in err or "rate" in err or "many requests" in err:
                _backoff(attempt)
                continue
            logger.warning("LeakCheck API error for %s: %s", value, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_breach",
                entity_key=node_id,
                error=str(e),
                service="LeakCheck",
            )
            break
        except Exception as e:
            logger.warning("LeakCheck attempt %s failed for %s: %s", attempt + 1, value, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_breach",
                entity_key=node_id,
                error=str(e),
                service="LeakCheck",
            )
            _backoff(attempt)

    # 3. BreachDirectory via RapidAPI
    r = None
    bd_key = os.environ.get("BREACHDIRECTORY_KEY", "")
    if bd_key:
        try:
            r = httpx_request(
                "GET",
                "https://breachdirectory.p.rapidapi.com/",
                params={"func": "auto", "term": value},
                headers={
                    "x-rapidapi-key": bd_key,
                    "x-rapidapi-host": "breachdirectory.p.rapidapi.com",
                },
                timeout=15,
            )
        except Exception as e:
            response_preview = (getattr(getattr(e, "response", None), "text", None) or "")[:500]
            logger.warning("BreachDirectory failed for %s: %s", value, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_breach",
                entity_key=node_id,
                error=str(e),
                service="BreachDirectory",
                response_preview=response_preview,
            )
            r = None
    else:
        r = None
    if r is not None and r.status_code == 200:
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
    elif r is not None:
        logger.warning("BreachDirectory non-200 for %s: %s", value, r.status_code)
        log_scan_event(
            scan_id,
            "resolver_failed",
            resolver="resolve_breach",
            entity_key=node_id,
            error=f"BreachDirectory status {r.status_code}",
            service="BreachDirectory",
            response_preview=(r.text or "")[:500],
        )

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
    node_payload = {
        "id": node_id,
        "type": entity_type,
        "value": value,
        "metadata": metadata,
        "depth": depth,
    }
    d[f"{NODE_PREFIX}{node_id}"] = node_payload
    write_stream_event(scan_id, "node", node_payload)

    d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch
    for edge in edges_batch:
        write_stream_event(scan_id, "edge", edge)

